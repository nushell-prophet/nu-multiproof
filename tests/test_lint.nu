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
# is caught. Rules with an `unless` also carry `interp_excused`: the offender
# next to the excuse token planted inside a `$"…"` — it MUST still be flagged,
# because prose naming a flag is not the flag.
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
        interp_excused: 'let msg = $"using --all"; let entries = ls $dir'
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
        interp_excused: 'let note = $"retry with --max-time"; let r = http get --full $url'
    }
    {
        name: "byte extraction must name its endianness"
        why: "`into binary` defaults to NATIVE, so `bytes at 0..0` takes the low byte only on a little-endian host. On a big-endian one it takes the high byte of an i64 — every varint byte becomes 0x00, every CID and OTS varuint is silently wrong, and nothing crashes."
        pattern: 'into binary.*bytes at'
        unless: '--endian'
        raw: false
        offender: 'let byte = $n | into binary | bytes at 0..0'
        allowed: 'let byte = $n | into binary --endian little | bytes at 0..0'
        interp_excused: 'let why = $"see --endian"; let byte = $n | into binary | bytes at 0..0'
    }
    {
        name: "no apostrophe in a def name"
        why: "nutest interpolates a test name into generated source as a bare block — `execute: { a sibling's bare signature }` — so an apostrophe opens a string that never closes and EVERY test in that file is reported failed, pointing at nutest's internals rather than at the name. Cost a diagnosis round twice in one session."
        # Backtick strings: this rule is about an apostrophe inside a quoted
        # name, so neither quote can be the delimiter. Both delimiters a name
        # can use are matched — a backtick-quoted name breaks nutest the same
        # way — and \x60 is the backtick, spelled that way so the pattern
        # itself needs no delimiter it cannot hold.
        pattern: `^\s*(export\s+)?def\s+("[^"]*'|\x60[^\x60]*')`
        unless: null
        raw: true
        offender: `def "a sibling's bare signature is not ours" [] {`
        allowed: `def "a sibling bare signature is not ours" [] {`
    }
]

# Blank out plain string bodies — every blanked character becomes a space, the
# delimiters stay — so all copies of a line keep the same length and a position
# found on one applies to the others. A construct written INSIDE a string is
# prose, not a call: `def "listing survives glob metacharacters"` is a test
# name and this file's own `offender:` samples are violations on purpose. Both
# used to be reported, which is why this file linted only the sources.
#
# Why a scan and not two `str replace --regex` passes, which is what this was:
# `"[^"]*"` pairs quotes blindly, so `$"a=\"x\" (ls $dir | get name)"` — the
# shape `tests/test_pubkey.nu:127` already writes — had its escaped quote read
# as a terminator, and the emptied span then swallowed the live `ls`. Measured:
# that line planted in a source file passed the linter. Two passes also lose to
# a mixed line (`let a = 'it"s'` before a `glob`, `"x'y"` after): whichever
# quote type goes first mis-pairs across the other's body. Blanking a linter
# does not fail loudly — it just stops finding things.
#
# An INTERPOLATED string keeps its body by default: `$"…(ls $dir)…"` holds a
# real call inside the parens, and a `$"…"` naming a forbidden construct as
# prose exists nowhere in this repo, so keeping it costs no false positive and
# closes the hole. `--prose` additionally blanks the interpolation's prose —
# what sits OUTSIDE its parens — while keeping paren contents: that is the copy
# excuses and the comment split are decided on, where only tokens in code
# position may count (the parens stay because `$"…(ls --all $dir)…"` carries
# its excuse inside them). Known limit, and the reason it is stated rather
# than handled: a string left open at end of line is blanked to the end of
# that line, and the line after it is read as code.
def blank-strings [--prose]: string -> string {
    mut out = ""
    mut delim = "" # the quote we are inside, "" when outside one
    mut interp = false # ...and whether a `$` opened it
    mut depth = 0 # paren nesting inside an interpolated string's body
    mut escaped = false
    mut prev = ""
    for c in ($in | split chars) {
        let in_code = $interp and ((not $prose) or $depth > 0)
        if $delim == "" {
            # Backticks are a string delimiter too — the apostrophe rule below
            # has to write both other quotes, so its own patterns use them.
            if $c in ['"' "'" '`'] {
                $delim = $c
                $interp = ($prev == '$')
            }
            $out = $out + $c
        } else if $escaped {
            # Only `"…"` honours a backslash; `'…'` and backticks take it raw.
            $escaped = false
            $out = $out + (if $in_code { $c } else { ' ' })
        } else if $c == '\' and $delim == '"' {
            $escaped = true
            $out = $out + (if $in_code { $c } else { ' ' })
        } else if $c == $delim {
            $delim = ""
            $interp = false
            $depth = 0
            $out = $out + $c
        } else if $interp {
            if $c == '(' { $depth = $depth + 1 }
            $out = $out + (if (not $prose) or $depth > 0 { $c } else { ' ' })
            if $c == ')' and $depth > 0 { $depth = $depth - 1 }
        } else {
            $out = $out + ' '
        }
        $prev = $c
    }
    $out
}

def violations [text: string]: nothing -> list<record> {
    $text
    | lines
    | enumerate
    | each {|it| {no: ($it.index + 1) text: $it.item} }
    | where not ($it.text | str trim | str starts-with "#")
    | each {|line|
        # Blanking only swaps string-body characters for spaces between
        # delimiters that stay put, so a line whose raw text holds the
        # construct nowhere cannot grow one. Skipping those keeps the scan off
        # ~99% of lines; the verdict is still decided on the blanked text —
        # `let x = "--all"` must not excuse the bare `ls` beside it.
        let candidates = $RULES | where $line.text =~ $it.pattern
        if ($candidates | is-empty) { [] } else {
            let code = $line.text | blank-strings
            # Excuses and the trailing-comment split are decided on the copy
            # with interpolation prose blanked too: a flag or a ` #` only
            # counts in code position. Splitting the RAW text on ` #` was
            # fail-open — `" #"` inside any string hid the rest of that line
            # from every rule — and `$"using --all"` beside a bare `ls` used
            # to excuse it, because the interpolation's prose was kept.
            let excuse = $line.text | blank-strings --prose
            let cut = $excuse | split row " #" | first | split chars | length
            let clip = {|s| $s | split chars | take $cut | str join }
            $candidates | each {|rule|
                let subject = do $clip (if $rule.raw { $line.text } else { $code })
                let hit = $subject =~ $rule.pattern
                let excused = $rule.unless != null and (do $clip $excuse | str contains $rule.unless)
                if $hit and not $excused {
                    {line: $line.no rule: $rule.name text: ($line.text | str trim)}
                }
            }
        }
    }
    | flatten
}

# Every .nu file in the repo: the scanned directories, walked all the way down
# so a future tests/helpers/ is not silently unlinted, plus the repo root
# itself, which is listed non-recursively and so contributes toolkit.nu alone.
def scanned-files [dir: path]: nothing -> list<path> {
    if $dir == $REPO_ROOT {
        list-files $dir --suffix ".nu"
    } else {
        list-files $dir --recursive --suffix ".nu"
    }
}

@test
def "known defect classes are absent from the sources and tests" [] {
    # A linter that finds no files passes vacuously — the exact shape of
    # "OK: all 0 objects verified" this repo shipped once already. Counted per
    # directory, not as one total: `list-files` answers [] for a directory that
    # is not there, so a renamed SCAN_DIRS entry would drop out of a combined
    # count of 39 and still clear a floor of 35.
    let files = [$REPO_ROOT] ++ ($SCAN_DIRS | each {|d| $REPO_ROOT | path join $d })
        | each {|d|
            let here = scanned-files $d
            assert ($here | is-not-empty) $"no .nu files found under ($d) — is it still there?"
            $here
        }
        | flatten
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

        # The excuse token planted inside a `$"…"` on the same line: prose, so
        # it must not excuse the real offender beside it. It did — interpolated
        # bodies are kept for matching, and the excuse was looked up on that
        # same copy.
        if $rule.unless != null {
            let on_interp = violations $rule.interp_excused | where rule == $rule.name
            assert ($on_interp | is-not-empty) $"rule '($rule.name)': its unless token inside an interpolated string excused the offender"
        }
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

# Every line here passed the two-regex stripper this replaced — the blanked
# span ran past where the string actually ended and took a live call with it.
# A linter that stops finding things says nothing while it does so, so the
# cases that broke it are pinned rather than remembered.
@test
def "a call the blanking used to swallow is still a violation" [] {
    # An escaped quote is not a terminator. This exact shape is written at
    # tests/test_pubkey.nu:127.
    assert equal (
        violations 'let names = $"a=\"x\" (ls $dir | get name)"' | get rule
    ) ["ls must pass --all"]

    # Mixed delimiters: neither "doubles first" nor "singles first" survives
    # this, because each quote type appears inside the other's body. Written
    # with backticks, the one delimiter that can hold both.
    assert equal (
        violations `let a = 'it"s' ; let hits = glob $pat ; let b = "x'y"` | get rule
    ) ["no glob pattern built from a path"]

    # A real call inside an interpolation is code, not prose.
    assert equal (violations 'print $"count: (ls $dir | length)"' | get rule) ["ls must pass --all"]

    # An `unless` token sitting inside a string excuses nothing.
    assert equal (violations 'let flag = "--all" ; ls $d' | get rule) ["ls must pass --all"]

    # The apostrophe rule covers both delimiters a def name can use; only the
    # double-quoted form is its offender sample.
    assert equal (
        violations "def `a sibling's bare signature is not ours` [] {" | get rule
    ) ["no apostrophe in a def name"]
}

# The comment split used to run on RAW text, so `" #"` inside any string cut
# the line there and hid everything after it from every rule — fail-open. The
# split point is now found on the fully-blanked copy, where only a real ` #`
# in code position survives.
@test
def "a hash inside a string does not hide the code after it" [] {
    assert equal (
        violations 'let d = "a #b"; let hits = glob $pat' | get rule
    ) ["no glob pattern built from a path"]

    # …nor does one inside an interpolated string's prose.
    assert equal (
        violations 'print $"item #(1) (ls $dir)"' | get rule
    ) ["ls must pass --all"]

    # A real trailing comment is still cut — excuse tokens in it and all.
    assert equal (violations 'ls $dir # add --all here' | get rule) ["ls must pass --all"]
}
