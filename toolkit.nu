export def main [] { }

# Requires nutest as sibling directory: git clone https://github.com/vyadh/nutest ../nutest
export def 'main test' [--fail] {
    use ../nutest/nutest

    if $fail {
        nutest run-tests --path tests/ --fail
    } else {
        nutest run-tests --path tests/
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
    --publish-to-ipfs # Publish content to local IPFS daemon (default: only-hash, no daemon needed)
] {
    use nu-multiproof/tree-hashes.nu

    tree-hashes root-cid --repo $repo --publish-to-ipfs=$publish_to_ipfs
}

export def 'main proof-extract' [
    ...files: string # Target file paths to prove
    --commit: string = "HEAD" # Commit to prove against
    --out-dir: path = "proof" # Output directory
] {
    use nu-multiproof/git-proof.nu

    git-proof extract ...$files --commit $commit --out-dir $out_dir
}

export def 'main proof-verify' [
    proof_dir: path = "proof" # Proof bundle directory
    --fail # Exit non-zero on an invalid proof (for CI)
] {
    use nu-multiproof/git-proof.nu

    git-proof verify $proof_dir --fail=$fail
}
