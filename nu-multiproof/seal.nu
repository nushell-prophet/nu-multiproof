use tree-hashes.nu
use merkle.nu
use ots.nu
use ssh-sign.nu
use _repo.nu repo-root
use _layout.nu [ manifest-path merkle-root-path ots-dir pubkeys-dir multiproofs-dir ]
use _sig.nu sig-files-for
use _fs.nu list-files
use _key-helpers.nu [ with-signing-key signing-principal ]
use _stamps.nu [ scan-stamps pick-stamp format-stamp ]
use _commit-proposal.nu seal-commit-line

# Full seal pipeline: hash+root-cid → sign → stamp.
#
# Operations order:
#   1. Upgrade pending OTS — opportunistic; tries all .ots files. "Still
#      pending" is silent (Bitcoin confirmation takes hours/days, so this just
#      progresses previous seals); any other failure is printed and skipped
#   2. tree-hashes — regenerate the manifest from current worktree files: one
#      in-process pass emits per-file, per-dir and the root "." row together, so
#      the manifest is written once, complete. Then derive the merkle root
#      statement (multiproofs/tree-root.txt) from the fresh manifest
#   3. ssh-sign — sign the root statement
#   4. ots stamp — timestamp the root statement AND every signature over it
#      (--no-stamp to skip), so the content and each endorsement are dated
#      separately. A proof commits to one file's hash, so two claims need two —
#      but both land in ONE bundle, the root statement's, so a single directory
#      answers "this content existed by T, and signer X endorsed it by T2"
#
# Committing is deliberately outside this pipeline. It's a user decision with
# context (message, scope, timing). `--propose-commit` does not weaken that: it
# writes the command into the prompt for the user to read, edit and run, and
# what it removes is a seal landing under "wip" or split over three commits,
# which makes the log useless for finding when a root was sealed.
#
# No --key and no --no-sign. The signing key comes from --repo's git config,
# which is where a repo's identity belongs, and `ssh-sign sign --key` still
# gives explicit key choice for a one-off. "Seal but do not sign" is
# `tree-hashes` followed by `merkle write-root` — the two commands this step
# wraps — so the flag bought a second name for a path that already exists.
# The live form is plain `seal` in an initialized repo — step 4 then posts the
# root statement's digest to the public OTS calendar, a permanent public write.
# That is why it is named here in prose and the example below stays offline:
# an @example must be pasteable into a throwaway directory without side
# effects beyond it.
@example "seal a throwaway repo, offline (drop --no-stamp for the calendar post)" {
    cd (mktemp --directory)
    git init -q
    git config user.email seal@example.com
    git config user.name sealer
    ssh-keygen -q -t ed25519 -N "" -f sealkey
    git config user.signingKey ./sealkey.pub
    "hello" | save file.txt
    git add file.txt
    git commit -q -m "init"
    nu-multiproof init
    nu-multiproof seal --no-stamp
}
export def main [
    --repo: path # Target git repo root (default: git root of current directory)
    --no-stamp # Skip OTS timestamping (on by default — seal should be complete)
    --response-file: path # Calendar answer for step 4, instead of posting the digest
    --propose-commit # Leave a `git commit` for this seal in the prompt, unrun
]: nothing -> record {
    let root = repo-root $repo
    let manifest_path = manifest-path $root
    let root_statement_path = merkle-root-path $root
    let ots_dir = ots-dir $root

    # Ask the signing question before touching anything. Step 2 rewrites the
    # manifest and the root statement and clears signatures over changed bytes;
    # when step 3 then discovered an unregistered key, the seal had already
    # left a regenerated manifest, a new unsigned root, and possibly a deleted
    # co-signer signature behind. Same check `ssh-sign sign` runs — asked
    # early, not enforced twice: sign keeps it for standalone use.
    # Bound rather than ignored: --propose-commit names the signer, and this is
    # the one place the principal comes from key material. Reading it back out
    # of `<file>.<fingerprint>.sig` would be the filename-as-identity shape this
    # repo removed.
    let signer = with-signing-key --root $root {|signing_key|
        signing-principal $signing_key (pubkeys-dir $root)
    }

    # Fingerprint every artifact regen rewrites, before regen: a sig covers
    # exact bytes, so it only goes stale when the bytes actually change. This is
    # what keeps the clearing step below from deleting a signature this seal did
    # not make and has no reason to touch — pinned by "seal keeps a co-signer
    # sig over unchanged bytes and clears it once they change".
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

    # 4. OTS timestamps — two of them, because an OTS proof commits to the hash
    # of one file and these are two separate claims:
    #   the root statement -> the CONTENT existed by T
    #   the signature      -> the ENDORSEMENT existed by T
    # Stamping only the root left the second unanswered. An SSH signature holds
    # no timestamp field, so a .sig made today fitted a year-old bundle and
    # nothing on disk contradicted it — which is exactly the claim that has to
    # survive a key compromise, where only a signature datable before the
    # revocation still means anything.
    #
    # Why two stamps rather than one object naming both files by digest: a
    # calendar aggregates every digest it receives into one merkle tree per
    # Bitcoin transaction, so the second post costs nothing on-chain and such an
    # object would only re-implement that batching a layer up — while adding an
    # artifact, a grammar and a parser. Two stamps also generalize for free:
    # every signature beside the root is stamped, so a co-signer's endorsement
    # is dated by the same loop, where a single object names one signature and
    # would need machinery per extra signer.
    #
    # Why not stamp the signature ALONE, which dates the content transitively:
    # it makes the most durable claim depend on the most fragile one. Content
    # time would stop being a bare hash compare and start needing the pubkey,
    # ssh-keygen and a key type OpenSSH still reads — three things that can rot
    # where a hash cannot, so a bundle that keeps a good key-free content anchor
    # today would then have none.
    #
    # The manifest is not stamped: the root is derived from every row, so its
    # anchor time-bounds the full CSV — the same argument that dropped the
    # whole-CSV signature. Archival tree-hashes.* bundles from the stamping era
    # stay.
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

        # Every signature over the root, not only the one step 3 just made: a
        # co-signer's endorsement is as undated as seal's own was, and this
        # loop is the whole cost of dating it. Shared discovery, so the bare
        # `<file>.sig` form is stamped too.
        #
        # Why --into the root's bundle instead of --out-dir: one seal moment is
        # one bundle. Derived naming gave each signature a bundle of its own,
        # keyed by a name that already carried the signer's 64-hex fingerprint —
        # so the fingerprint appeared three times in one tree, the .sig appeared
        # twice, and neither directory could make the whole claim README calls
        # the bundle contract: the content bundle held an endorsement it could
        # not date, and the signature bundle held a date for content it did not
        # carry. Stamping into the content's bundle puts all four files together
        # and costs nothing elsewhere — `merkle verify` matches proofs by content
        # commitment over one directory level, never by bundle name.
        let sig_stamps = sig-files-for $root_statement_path | each {|sig|
                ots stamp $sig --into $root_stamp.dir --response-file $response_file | get ots
            }
        $result = ($result | insert sig_ots $sig_stamps)
    }

    # Last, so the buffer holds the proposal for a seal that finished. Outside a
    # REPL this is harmless rather than a no-op: `commandline edit` writes the
    # engine's repl buffer unconditionally, and only the REPL ever reads it back
    # — so the flag is inert in a script without being an error there.
    if $propose_commit {
        # No --replace: replacing is `commandline edit`'s documented default, so
        # naming it would imply a choice was made among its four modes. The one
        # that must never appear here is --accept, which runs the buffer
        # immediately — the opposite of the guarantee this flag exists for.
        commandline edit (seal-commit-line $result $root $signer)
    }

    $result
}

# What the multiproofs/ folder holds: one row per bundle, with the anchor state
# of the content it froze and of each signature beside it.
#
# Why this exists: the folder answers "is this sealed, and is it dated yet" only
# by reading long directory names and running `ots info` by hand. `merkle verify`
# answers it for one proof against one root; this answers it for everything on
# disk, which is what a person opening the folder actually wants to know.
#
# Read-only, and deliberately NOT a verdict. It reports what the files say — no
# signature is checked here, so `signers` counts signature *files* and never
# claims a signature is valid or names who made it. A name on disk is not
# evidence of a signer (that is why a principal is a key's fingerprint), so the
# command that renders a name must not be the one that vouches for it: use
# `ssh-sign verify` or `merkle verify` for verdicts.
#
# Columns:
#   bundle   — directory under multiproofs/, relative to the repo root
#   file     — the frozen content snapshot in it
#   current  — the live artifact of that name under multiproofs/ has these exact
#              bytes, i.e. this is the seal in force rather than a previous one
#   content  — anchor over the snapshot: `absent`, `pending`, or `anchored
#              <height>` — the Bitcoin block the proof binds to. That height is
#              the only time an .ots carries; a block's wall-clock time is in its
#              header, which no proof holds, so a date needs `ots verify` and the
#              network. This command stays offline, so it reports the height
#   signers  — how many signature files sit in the bundle
#   endorsed — anchor over each of those signatures, same order, comma-joined,
#              and empty when `signers` is 0. A string and not a list because a
#              list cell renders as "[list 1 item]", which hides the one thing the
#              column exists to show; the values are still exact, so `where
#              endorsed =~ anchored` works
#
# A bundle whose only stamped content is a signature — the layout `seal` wrote
# before the two anchors shared a directory — reads `file: null, content: absent`
# with `signers: 1` and a dated `endorsed`. That is the honest shape: it carries
# an endorsement and its date but no content snapshot, and `signers` is what
# separates it from a bundle holding nothing.
#
# Bundles reached through a symlinked directory are not listed: `list-files
# --recursive` descends real directories only, for the same reason `--regular`
# drops symlinked files below.
#
# Not a `list` subcommand: `list` is a Nushell type keyword, and this returns a
# join over three sources rather than a listing of one.
@example "report a throwaway repo with nothing sealed yet" {
    cd (mktemp --directory)
    git init -q
    mkdir multiproofs
    nu-multiproof seal status
}
export def status [
    --repo: path # Target git repo root (default: git root of current directory)
]: nothing -> table {
    let root = repo-root $repo
    let mp = multiproofs-dir $root

    # Why --recursive here where `merkle verify` walks one level: verify consults
    # the operational set under ots-timestamps/, while this describes the whole
    # folder — including archival trees like origin-proofs/, which a person can
    # see and would otherwise wonder why the report omits. Real directories only,
    # so a bundle behind a symlink is not listed.
    let stamps = scan-stamps $mp --recursive

    # Bundles are the directories those proofs live in, discovered from the
    # proofs rather than from a name pattern — the same reason verify matches by
    # content commitment. A directory holding no proof is not a bundle.
    $stamps | get file | each {|f| $f | path dirname } | uniq | sort | each {|dir|
        # --regular: every path below is opened and its bytes read as that name's
        # own content, and a symlink's are not. Without it a link to a directory
        # (nushell types it `symlink`, not `dir`) or a dangling one reached `open`
        # and threw "Eval block failed with pipeline input", naming no file — a
        # report that describes the archive must not die on it.
        let files = list-files $dir --regular
        let sigs = $files | where ($it | path basename | str ends-with ".sig") | sort
        let here = $stamps | where ($it.file | path dirname) == $dir
        # The snapshot is the non-signature file a proof in this bundle commits
        # to — the same content-commitment rule the rest of this layer discovers
        # by, not "the first file that is neither a proof nor a signature". That
        # positional reading let any stray file in a bundle become the reported
        # snapshot, and then its unanchored hash reported the bundle's content as
        # `absent` while the real frozen copy sat beside it anchored. A file no
        # proof commits to is not what the bundle attests, so it is not named
        # here; a bundle with none reports `null` (the oldest ones, see README).
        let candidates = $files
            | where not ($it | path basename | str ends-with ".ots")
            | where not ($it | path basename | str ends-with ".sig")
            | each {|f| {file: $f hash: (open --raw $f | hash sha256)} }
            | where $it.hash in ($here | get hash)
        # More than one stamped non-signature file in a bundle is what --into
        # permits, and `get 0?` then picked by `ls` order — so a bundle could
        # report a file it is not named after and drop the other anchor silently.
        # The bundle's own name settles it: it is `<stem>.<8 hex of the hash>`,
        # and that hash is this bundle's reason to exist. Uppercase in the name,
        # lowercase from `hash sha256`, hence the fold.
        #
        # Applied unconditionally, not only when there are several candidates: the
        # filter can only shrink the set, and an empty result falls back to the
        # old reading, so a bundle whose name carries no `.<8 hex>` — a hand-made
        # one — behaves exactly as before instead of taking a second code path.
        let prefix = $dir | path basename | parse --regex '\.(?<p>[0-9A-Fa-f]{8})$' | get p?.0? | default ""
        let keyed = $candidates
            | where $prefix != "" and ($it.hash | str starts-with ($prefix | str lowercase))
        let snapshot = ($keyed | get 0?) | default ($candidates | get 0?)
        {
            bundle: ($dir | path relative-to $root)
            file: (if $snapshot == null { null } else { $snapshot.file | path basename })
            # null, not false, when there is nothing to compare against: `false`
            # reads as "a later seal superseded this", and a bundle over a file
            # that is not a multiproofs/ top-level artifact has no live
            # counterpart at all.
            current: (
                if $snapshot == null { null } else {
                    let live = $mp | path join ($snapshot.file | path basename)
                    if not ($live | path exists) { null } else {
                        (open --raw $live | hash sha256) == $snapshot.hash
                    }
                }
            )
            content: (
                if $snapshot == null { "absent" } else {
                    format-stamp (pick-stamp ($here | where hash == $snapshot.hash))
                }
            )
            signers: ($sigs | length)
            endorsed: (
                $sigs | each {|s|
                    format-stamp (pick-stamp ($here | where hash == (open --raw $s | hash sha256)))
                } | str join ", "
            )
        }
    }
}
