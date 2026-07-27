use std/assert
use std/testing *
use ../nu-multiproof/_fs.nu list-files

# Source-level rules for defect classes this repo has shipped more than once.
#
# Why a test and not a CLAUDE.md line: CLAUDE.md already names every trap below,
# and every one of them was reintroduced afterwards anyway — the glob trap at
# eight sites, the temp-leak shape five times, the error rewrap four times. A
# rule an agent must remember is not a rule; this one runs in CI.
#
# Scope: it reads text, so it catches the pattern, not the intent. Keep the
# rules narrow enough that a match is always a defect. Anything needing real
# parsing belongs in a behavioural test instead.

# Sources AND tests. A test writes the same `ls` and the same `glob` a source
# does, and gets them wrong the same way — test_seal.nu asserted `(glob …|
# length) == 0` twice, which a glob matching nothing satisfies for the wrong
# reason. tests-network/ and toolkit.nu are in for the same reason; the repo
# root is listed non-recursively, so it contributes toolkit.nu alone.
const REPO_ROOT = (path self ..)
const SCAN_DIRS = ["nu-multiproof" "tests" "tests-network"]

# Each rule: `pattern` marks the suspect construct, `unless` (when set) is what
# makes it acceptable on the same line. `raw` opts out of the string stripping
# below, for a rule whose subject IS a string literal. `offender`/`allowed` are
# samples the rules are tested against, so a rule that silently stops matching
# is caught.
const RULES = [
    {
        name: "no glob pattern built from a path"
        why: "interpolating a directory into a glob pattern makes `[`, `]`, `*`, `?` in that path read as pattern syntax — the call then silently matches nothing. Use _fs.nu list-files / list-dirs."
        pattern: '(^|[\s(|])glob\s'
        unless: null
        raw: false
        offender: 'let keys = glob ($pubkeys_dir | path join "*.pub")'
        allowed: 'let keys = list-files $pubkeys_dir --suffix ".pub"'
    }
    {
        name: "ls must pass --all"
        why: "plain `ls` hides dotfiles, so `.env.alice.sig` was invisible to signature discovery and a stale sig survived seal's clearing step."
        pattern: '(^|[\s(|])ls\s'
        unless: '--all'
        raw: false
        offender: 'let entries = ls $dir | get name'
        allowed: 'let entries = ls --all $dir | get name'
    }
    {
        name: "no error rewrap that drops the original"
        why: "`error make {msg: $e.msg}` discards the span, labels, help text and inner error. For cleanup use `try { … } finally { … }`."
        pattern: 'error make \{\s*msg:\s*\$[A-Za-z_][A-Za-z0-9_]*\.msg'
        unless: null
        raw: false
        offender: 'catch {|e| rm --force $tmp; error make {msg: $e.msg} }'
        allowed: 'try { work } finally { rm --force $tmp }'
    }
    {
        name: "http calls must be bounded"
        why: "a black-holed connection hangs stamp/upgrade/verify with no output, and seal runs upgrade in a loop over every archived stamp."
        pattern: 'http (get|post|put|patch|delete|head)\s'
        unless: '--max-time'
        raw: false
        offender: 'let r = http get --full $url'
        allowed: 'let r = http get --full --max-time $NETWORK_TIMEOUT $url'
    }
    {
        name: "byte extraction must name its endianness"
        why: "`into binary` defaults to NATIVE, so `bytes at 0..0` takes the low byte only on a little-endian host. On a big-endian one it takes the high byte of an i64 — every varint byte becomes 0x00, every CID and OTS varuint is silently wrong, and nothing crashes."
        pattern: 'into binary.*bytes at'
        unless: '--endian'
        raw: false
        offender: 'let byte = $n | into binary | bytes at 0..0'
        allowed: 'let byte = $n | into binary --endian little | bytes at 0..0'
    }
    {
        name: "no apostrophe in a def name"
        why: "nutest interpolates a test name into generated source as a bare block — `execute: { a sibling's bare signature }` — so an apostrophe opens a string that never closes and EVERY test in that file is reported failed, pointing at nutest's internals rather than at the name. Cost a diagnosis round twice in one session."
        # Backtick strings: this rule is about an apostrophe inside a
        # double-quoted name, so neither quote can be the delimiter.
        pattern: `^\s*(export\s+)?def\s+"[^"]*'`
        unless: null
        raw: true
        offender: `def "a sibling's bare signature is not ours" [] {`
        allowed: `def "a sibling bare signature is not ours" [] {`
    }
]

# Drop whole-line comments and trailing ` # …`. Deliberately crude: it can cut a
# line short at a `#` inside a string, which only ever hides code from a rule —
# it cannot invent a violation.
def strip-comments []: string -> list<record<no: int, text: string>> {
    lines
    | enumerate
    | each {|it| {no: ($it.index + 1) text: $it.item} }
    | where {|l| not ($l.text | str trim | str starts-with "#") }
    | each {|l| {no: $l.no text: ($l.text | split row " #" | first)} }
}

# Empty out quoted string bodies, keeping the quotes. A construct written
# INSIDE a string is prose, not a call: `def "listing survives glob
# metacharacters"` is a test name and this file's own `offender:` samples are
# violations on purpose. Both used to be reported, which is why this file
# linted only the sources.
#
# Same crude-but-safe property as strip-comments: `[^"]*` cannot span a quote,
# so each pair is emptied on its own and an odd quote at worst hides code from
# a rule. It cannot invent a violation, and a real call keeps its command word
# — `glob $"($dir)/*"` becomes `glob $""`, which still matches.
def strip-strings []: string -> string {
    str replace --all --regex '"[^"]*"' '""' | str replace --all --regex "'[^']*'" "''"
}

def violations [text: string]: nothing -> list<record> {
    $text
    | strip-comments
    | each {|line|
        let code = $line.text | strip-strings
        $RULES | each {|rule|
            let subject = if $rule.raw { $line.text } else { $code }
            let hit = $subject =~ $rule.pattern
            let excused = $rule.unless != null and ($subject | str contains $rule.unless)
            if $hit and not $excused {
                {line: $line.no rule: $rule.name text: ($line.text | str trim)}
            }
        }
    }
    | flatten
}

# Every .nu file in the repo: the three scanned directories plus the repo root
# itself, which is listed non-recursively and so contributes toolkit.nu alone.
def scanned-files []: nothing -> list<path> {
    [$REPO_ROOT] ++ ($SCAN_DIRS | each {|d| $REPO_ROOT | path join $d })
    | each {|d| list-files $d --suffix ".nu" }
    | flatten
}

@test
def "known defect classes are absent from the sources and tests" [] {
    let files = scanned-files
    # A linter that finds no files passes vacuously — the exact shape of
    # "OK: all 0 objects verified" this repo shipped once already.
    assert (($files | length) >= 35) $"only ($files | length) .nu files found under ($REPO_ROOT)"

    let found = $files | each {|f|
        violations (open --raw $f) | each {|v| $v | insert file ($f | path basename) }
    } | flatten

    let report = $found
        | each {|v| $"  ($v.file):($v.line) [($v.rule)] ($v.text)" }
        | str join (char newline)
    assert equal $found [] $"lint violations:(char newline)($report)"
}

# The rules are text patterns, so a typo makes them match nothing and the suite
# stays green while the class is wide open. Each rule carries a sample of the
# construct it forbids and of the accepted replacement.
@test
def "every rule matches its offender and clears its allowed form" [] {
    for rule in $RULES {
        let on_offender = violations $rule.offender | where rule == $rule.name
        assert ($on_offender | is-not-empty) $"rule '($rule.name)' does not match its own offender sample"

        let on_allowed = violations $rule.allowed | where rule == $rule.name
        assert ($on_allowed | is-empty) $"rule '($rule.name)' rejects its own allowed sample"
    }
}

@test
def "a comment naming a forbidden construct is not a violation" [] {
    assert equal (violations '# Not `glob $"($path).*.sig"` because: the path is data') []
    assert equal (violations 'let x = 1 # was: ls $dir') []
}

# The other half of the same rule, and what kept this file out of tests/ until
# now: a construct named inside a string is prose. Both cases below are real —
# the first is a test name in test_fs.nu, the second this file's own sample.
@test
def "a forbidden construct inside a string literal is not a violation" [] {
    assert equal (violations 'def "listing works when the directory name holds glob metacharacters" [] {') []
    assert equal (violations "        offender: 'let entries = ls $dir | get name'") []
    # …but the call around the string still counts.
    assert equal (violations 'let hits = glob $"($dir)/*.pub"' | get rule) ["no glob pattern built from a path"]
}
