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

const MODULE_DIR = (path self ..) | path join "nu-multiproof"

# Each rule: `pattern` marks the suspect construct, `unless` (when set) is what
# makes it acceptable on the same line. `offender`/`allowed` are samples the
# rules are tested against, so a rule that silently stops matching is caught.
const RULES = [
    {
        name: "no glob pattern built from a path"
        why: "interpolating a directory into a glob pattern makes `[`, `]`, `*`, `?` in that path read as pattern syntax — the call then silently matches nothing. Use _fs.nu list-files / list-dirs."
        pattern: '(^|[\s(|])glob\s'
        unless: null
        offender: 'let keys = glob ($pubkeys_dir | path join "*.pub")'
        allowed: 'let keys = list-files $pubkeys_dir --suffix ".pub"'
    }
    {
        name: "ls must pass --all"
        why: "plain `ls` hides dotfiles, so `.env.alice.sig` was invisible to signature discovery and a stale sig survived seal's clearing step."
        pattern: '(^|[\s(|])ls\s'
        unless: '--all'
        offender: 'let entries = ls $dir | get name'
        allowed: 'let entries = ls --all $dir | get name'
    }
    {
        name: "no error rewrap that drops the original"
        why: "`error make {msg: $e.msg}` discards the span, labels, help text and inner error. For cleanup use `try { … } finally { … }`."
        pattern: 'error make \{\s*msg:\s*\$[A-Za-z_][A-Za-z0-9_]*\.msg'
        unless: null
        offender: 'catch {|e| rm --force $tmp; error make {msg: $e.msg} }'
        allowed: 'try { work } finally { rm --force $tmp }'
    }
    {
        name: "http calls must be bounded"
        why: "a black-holed connection hangs stamp/upgrade/verify with no output, and seal runs upgrade in a loop over every archived stamp."
        pattern: 'http (get|post|put|patch|delete|head)\s'
        unless: '--max-time'
        offender: 'let r = http get --full $url'
        allowed: 'let r = http get --full --max-time $NETWORK_TIMEOUT $url'
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

def violations [text: string]: nothing -> list<record> {
    $text
    | strip-comments
    | each {|line|
        $RULES | each {|rule|
            let hit = $line.text =~ $rule.pattern
            let excused = $rule.unless != null and ($line.text | str contains $rule.unless)
            if $hit and not $excused {
                {line: $line.no rule: $rule.name text: ($line.text | str trim)}
            }
        }
    }
    | flatten
}

@test
def "known defect classes are absent from the sources" [] {
    let files = list-files $MODULE_DIR --suffix ".nu"
    # A linter that finds no files passes vacuously — the exact shape of
    # "OK: all 0 objects verified" this repo shipped once already.
    assert (($files | length) >= 15) $"only ($files | length) module files found under ($MODULE_DIR)"

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
