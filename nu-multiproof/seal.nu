use tree-hashes.nu
use merkle.nu
use ots.nu
use ssh-sign.nu
use _repo.nu repo-root
use _layout.nu [manifest-path merkle-root-path ots-dir pubkeys-dir]
use _sig.nu sig-files-for
use _fs.nu list-files
use _key-helpers.nu with-signing-key

# Full seal pipeline: hash+root-cid → sign → stamp.
#
# Operations order:
#   1. Upgrade pending OTS — opportunistic; tries all .ots files, silent on failure
#      (Bitcoin confirmation takes hours/days, so this progresses previous seals)
#   2. tree-hashes — regenerate the manifest from current worktree files: one
#      in-process pass emits per-file, per-dir and the root "." row together, so
#      the manifest is written once, complete. Then derive the merkle root
#      statement (multiproofs/tree-root.txt) from the fresh manifest
#   3. ssh-sign — sign the root statement
#   4. ots stamp — timestamp the root statement (--no-stamp to skip)
#
# Committing is deliberately outside this pipeline. It's a user decision with
# context (message, scope, timing).
#
# No --key and no --no-sign. The signing key comes from --repo's git config,
# which is where a repo's identity belongs, and `ssh-sign sign --key` still
# gives explicit key choice for a one-off. "Seal but do not sign" is
# `tree-hashes` followed by `merkle write-root` — the two commands this step
# wraps — so the flag bought a second name for a path that already exists.
@example "full seal of the current repo" { seal }
@example "seal without timestamping" { seal --no-stamp }
export def main [
    --repo: path # Target git repo root (default: git root of current directory)
    --no-stamp # Skip OTS timestamping (on by default — seal should be complete)
    --response-file: path # Calendar answer for step 4, instead of posting the digest
] {
    let root = repo-root $repo
    let manifest_path = manifest-path $root
    let root_statement_path = merkle-root-path $root
    let ots_dir = ots-dir $root

    # Fingerprint every artifact regen rewrites, before regen: a sig covers
    # exact bytes, so it only goes stale when the bytes actually change. This is
    # what lets --no-sign mean "skip signing" instead of "remove still-valid
    # signatures" on an unchanged reseal (see the clearing step below).
    let regen_targets = [$root_statement_path $manifest_path]
    let pre_hashes = $regen_targets | each {|f|
        if ($f | path exists) { open --raw $f | hash sha256 } else { "" }
    }

    # 1. Upgrade pending OTS — every seal progresses previous seals automatically,
    #    so there's no need for a separate upgrade command
    if ($ots_dir | path exists) {
        list-files $ots_dir --recursive --suffix ".ots" | each {|ots_file|
            try { ots upgrade $ots_file } catch {|e|
                # Why: "not yet confirmed" is the normal case — Bitcoin
                # confirmation takes hours/days, so skip it quietly. Anything
                # else (corrupt proof, network misconfig, parse bug) is a real
                # problem; surface it instead of swallowing (fail-fast).
                if not ($e.msg | str contains "not yet confirmed") {
                    print $"upgrade failed for ($ots_file): ($e.msg)"
                }
            }
        }
    }

    # 2. Regenerate the manifest in one pass: per-file, per-dir AND the root "."
    #    row together, so the manifest is written once,
    #    complete, before any signature exists.
    let root_cid = tree-hashes root-cid --repo $root
    print $"Root CID: ($root_cid)"
    print $"Manifest: ($manifest_path)"
    mut result = {manifest: $manifest_path root_cid: $root_cid}

    # Derive the merkle root statement from the fresh manifest — the compact
    # signing target: consumers verify per-file inclusion proofs against this
    # 32-byte commitment instead of keeping the whole CSV (see merkle.nu).
    # Immediately after regen, so no window where the statement describes a
    # previous manifest.
    let merkle_result = merkle write-root --repo $root
    print $"Merkle root: ($merkle_result.root)"
    $result = ($result | insert merkle_root $merkle_result.root)

    # Why: a sig from a previous seal signs the previous bytes — stale exactly
    # when regen changed them. Clear those before step 3 signs fresh; sigs
    # over unchanged bytes are still valid and survive, whoever made them — a
    # co-signer's sig is not this seal's to delete. Uses the shared discovery
    # so the bare `.sig` form is cleared too, not just `.<signer>.sig`.
    #
    # Why the manifest goes through the same rule instead of being swept
    # unconditionally: `ssh-sign sign multiproofs/tree-hashes.csv` is a public
    # command, and the sweep deleted a signature the user made deliberately,
    # saying nothing — it read "leftover from the era when seal signed the CSV"
    # into a file that only says who signed which bytes. Bytes are the one thing
    # a seal can check: unchanged bytes mean the sig still verifies, whoever
    # made it and whenever; changed bytes make it stale wherever it came from.
    # Frozen copies inside OTS bundle dirs stay — they're archival.
    #
    # Why it prints: this deletes signed evidence, and the previous silence is
    # how a deliberate signature could go without anyone noticing.
    $regen_targets | zip $pre_hashes | each {|pair|
        if (open --raw $pair.0 | hash sha256) != $pair.1 {
            sig-files-for $pair.0 | each {|sig|
                rm $sig
                print $"Cleared stale signature: ($sig | path relative-to $root)"
            }
        }
    }

    # 3. Sign the root statement — the one signed artifact. The root is
    # derived from every manifest row (the "." root-CID row included), so it
    # authenticates the full CSV indirectly: rebuild the tree, compare roots.
    # The transitional whole-CSV signature was dropped as unneeded legacy.
    # Why resolve here and not let `ssh-sign sign` do it: the key comes from
    # --repo's git config, and ssh-sign reads the CWD's repo. The closure form
    # bounds an inline `key::` temp file to the signing call.
    # Why pass pubkeys-dir explicitly: ssh-sign sign defaults to the CWD's git
    # root, but seal may target a different repo via --repo.
    let root_sig = with-signing-key --root $root {|signing_key|
        ssh-sign sign $root_statement_path --key $signing_key --pubkeys-dir (pubkeys-dir $root)
    }
    $result = ($result | insert root_sig $root_sig)

    # 4. OTS timestamp — anchors the root statement to Bitcoin. The manifest
    # is not stamped: the root is derived from every row, so its anchor
    # time-bounds the full CSV — the same argument that dropped the whole-CSV
    # signature. Archival tree-hashes.* bundles from the stamping era stay.
    # Why pass out-dir explicitly: ots stamp defaults it to the CWD's git root,
    # but seal may target a different repo via --repo (same fix as pubkeys-dir
    # in step 3). Without it, `seal --repo /other` writes the bundle into the
    # CWD's repo, or fails when CWD is not a repo.
    #
    # Why --response-file is forwarded: without it the only way to reach this
    # step is a live calendar, so the whole of it — the out-dir choice, the
    # frozen copy, the sig snapshot — went untested, and `--repo /other`
    # writing its bundle into the CWD's repo was found by reading, not by the
    # suite. Same test seam, and same argument, as `ots stamp --response-file`.
    if not $no_stamp {
        let root_stamp = ots stamp $root_statement_path --out-dir $ots_dir --response-file $response_file
        $result = ($result | insert root_ots $root_stamp.ots)
    }

    $result
}
