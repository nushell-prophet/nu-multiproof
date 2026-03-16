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

# Resolve SSH signing key from git config (file path or inline key::)
def resolve-signing-key [root: path]: nothing -> record<key: string, name: string> {
    let git_key = (do { ^git -C $root config user.signingKey } | complete)
    if $git_key.exit_code != 0 {
        error make {msg: "no git signing key configured — use --no-sign or set user.signingKey"}
    }
    let raw = $git_key.stdout | str trim
    if ($raw | str starts-with "key::") {
        let key_data = $raw | str replace "key::" ""
        let tmp = $nu.temp-dir | path join "seal-signing-key.pub"
        $key_data | save --raw --force $tmp
        {key: $tmp, name: null}
    } else {
        let expanded = $raw | path expand
        let key_path = if ($expanded | path exists) { $expanded
        } else if ($"($expanded).pub" | path exists) { $"($expanded).pub"
        } else {
            error make {msg: $"signing key not found: ($raw)"}
        }
        {key: ($key_path | into string), name: null}
    }
}

# Full seal pipeline: hash → root-cid → sign → stamp.
#
# Operations order:
#   1. Upgrade pending OTS — opportunistic; tries all .ots files, silent on failure
#      (Bitcoin confirmation takes hours/days, so this progresses previous seals)
#   2. tree-hashes — regenerate manifest from current worktree files
#   3. root-cid — compute IPFS root CID, append "." row to manifest
#   4. ssh-sign — sign the manifest (on by default; --no-sign to skip)
#   5. ots stamp — timestamp the manifest (on by default; --no-stamp to skip)
#
# Committing is deliberately outside this pipeline. It's a user decision with
# context (message, scope, timing). Also avoids circularity: git-proof proves
# files existed in a signed commit, but seal artifacts would need to be in
# that commit — keeping them separate sidesteps the chicken-and-egg.
export def 'main seal' [
    --path: path       # Target directory (default: current directory)
    --key: path        # SSH private key (default: from git config user.signingKey)
    --no-sign          # Skip SSH signing (on by default — seal should be complete)
    --no-stamp         # Skip OTS timestamping (on by default — seal should be complete)
    --only-hash        # Compute root CID without adding to IPFS
] {
    use nu-multiproof/tree-hashes.nu
    use nu-multiproof/ots.nu
    use nu-multiproof/ssh-sign.nu

    let root = if $path != null { $path | path expand } else {
        ^git rev-parse --show-toplevel | str trim
    }
    let manifest_path = $root | path join "multiproofs/tree-hashes.csv"
    let ots_dir = $root | path join "multiproofs/ots-timestamps"

    # 1. Upgrade pending OTS — every seal progresses previous seals automatically,
    #    so there's no need for a separate upgrade command
    if ($ots_dir | path exists) {
        glob ($ots_dir | path join "**/*.ots") | each {|ots_file|
            try { ots upgrade $ots_file } catch { }
        }
    }

    # 2. Regenerate manifest — must precede root-cid (provides the file list)
    tree-hashes --path $root
    print $"Manifest: multiproofs/tree-hashes.csv"

    # 3. Compute root CID — single IPFS hash covering all manifest files
    let root_cid = tree-hashes root-cid --path $root --only-hash=$only_hash
    print $"Root CID: ($root_cid)"

    mut result = {root_cid: $root_cid, manifest: $manifest_path}

    # 4. Sign the manifest — covers root CID via the "." row
    if not $no_sign {
        let resolved = if $key != null {
            {key: ($key | into string), name: null}
        } else {
            resolve-signing-key $root
        }
        let sig = if $resolved.name != null {
            ssh-sign sign $manifest_path --key $resolved.key --name $resolved.name
        } else {
            ssh-sign sign $manifest_path --key $resolved.key
        }
        $result = ($result | insert sig $sig)
    }

    # 5. OTS timestamp — anchors the manifest (with root CID) to Bitcoin
    if not $no_stamp {
        let stamp_result = ots stamp $manifest_path
        $result = ($result | insert ots $stamp_result.ots)
    }

    $result
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
