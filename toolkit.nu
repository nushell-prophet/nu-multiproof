export def main [] { }

# Requires nutest as sibling directory: git clone https://github.com/vyadh/nutest ../nutest
#
# --network runs tests-network/ instead: tests that reach the public internet,
# one of which writes a permanent timestamp to a public calendar. Kept out of
# the default run for that reason, not because they are optional.
#
# Why --fail is the default now, with --no-fail to opt out: `main test` used to
# exit 0 on a failing suite, so a run with 45 failures in it read as success to
# anything that only looked at the exit code — including an agent.
export def 'main test' [--network --no-fail] {
    use ../nutest/nutest

    let path = if $network { "tests-network/" } else { "tests/" }
    if $no_fail {
        nutest run-tests --path $path
    } else {
        nutest run-tests --path $path --fail
    }
}
