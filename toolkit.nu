export def main [] {}

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
    path: path
    --out-dir: string   # Default: multiproofs/ots-timestamps from git root
    --key: string   # SSH private key path for signing (optional)
    --name: string  # Signer name for .sig file (default: key filename stem)
] {
    use nu-multiproof/ots.nu
    use nu-multiproof/ssh-sign.nu

    let result = ots stamp $path --out-dir $out_dir
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
    --path: path  # Target directory (default: current directory)
] {
    use nu-multiproof/tree-hashes.nu

    tree-hashes --echo=$echo --path $path
}

export def 'main root-cid' [
    --path: path       # Target directory (default: current directory)
    --only-hash        # Compute CID without adding content to IPFS
] {
    use nu-multiproof/tree-hashes.nu

    tree-hashes root-cid --path $path --only-hash=$only_hash
}

export def 'main proof-extract' [
    ...files: string            # Target file paths to prove
    --commit: string = "HEAD"   # Commit to prove against
    --out-dir: string = "proof" # Output directory
] {
    use nu-multiproof/git-proof.nu

    git-proof extract ...$files --commit $commit --out-dir $out_dir
}

export def 'main proof-verify' [
    proof_dir: string = "proof"  # Proof bundle directory
] {
    use nu-multiproof/git-proof.nu

    git-proof verify $proof_dir
}
