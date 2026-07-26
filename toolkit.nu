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

export def 'main stamp' [
    file: path
    --out-dir: path # Default: multiproofs/ots-timestamps from git root
    --key: string # SSH private key path for signing (optional)
    --name: string # Signer name for .sig file (default: stem of matching pubkey in multiproofs/pubkeys/)
] {
    use nu-multiproof/ots.nu
    use nu-multiproof/ssh-sign.nu

    let result = ots stamp $file --out-dir $out_dir
    if $key != null {
        if $name != null {
            ssh-sign sign $result.copy --key $key --name $name
        } else {
            ssh-sign sign $result.copy --key $key
        }
    }
    $result
}

export def 'main hash' [
    --echo
    --repo: path # Target git repo root (default: git root of current directory)
] {
    use nu-multiproof/tree-hashes.nu

    tree-hashes --echo=$echo --repo $repo
}

export def 'main root-cid' [
    --repo: path # Target git repo root (default: git root of current directory)
] {
    use nu-multiproof/tree-hashes.nu

    tree-hashes root-cid --repo $repo
}
