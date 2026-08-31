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
# Why one thread by default: nutest's own default runs every suite in parallel
# and every test inside it in parallel too, which fires roughly 1500 short-lived
# processes in 3.5 seconds. Under Apple `container` that wedges the terminal of
# the whole VM on the fourth or fifth consecutive run — the guest keeps running,
# but nothing it prints reaches the screen again until the machine is restarted.
# Thirty consecutive single-threaded runs never wedged it. The suite then takes
# 17 seconds instead of 4, which is the price of a terminal that survives.
# Pass --threads 0 for the old behaviour (0 means one per core).
# Investigated in cozy/todo/20260830-debug-freeze.md; the fault is in the
# runtime, not here, so this default should go once it is fixed upstream.
export def 'main test' [--network --no-fail --threads: int = 1] {
    use ../nutest/nutest

    let path = if $network { "tests-network/" } else { "tests/" }
    let strategy = {threads: $threads}
    if $no_fail {
        nutest run-tests --path $path --strategy $strategy
    } else {
        nutest run-tests --path $path --strategy $strategy --fail
    }
}
