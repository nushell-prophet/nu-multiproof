# nu-multiproof

Proof of concept: Composable cryptographic proofs for git repositories, written in Nushell. No external dependencies beyond `git`, `ssh-keygen` and `chmod` — network calls use Nushell's built-in `http`.

🚧 The code in this repo was generated via `claude code` and has never been reviewed by an outside cryptographer — do not rely on it for anything that matters. It is not untested: it has some tests, and the hostile artifacts are hand-built rather than produced by this repo's own builder. That establishes the guards do something, not that the design is sound.

## What you can prove

| Claim | Proof type | Mechanism |
|-------|-----------|-----------|
| **This content existed at a specific time** | OpenTimestamps | Hash chain anchored to a Bitcoin block header |
| **This file was in the catalogued snapshot** | Merkle inclusion proof | RFC 6962-style binary tree over the manifest rows; one signed 32-byte root verifies a proof of ~log2(n) hashes |

Each proof type is independent. Use either or both.

`ssh-sign` is not a third claim — it is the signing step under both. It signs a file with an SSH key, and verifies every `.sig` beside a file against the keys in `multiproofs/pubkeys/`, separating "content changed" from "key not registered". `seal` uses it to sign the root statement and `merkle verify` to check that signature. It also runs standalone on any file.

A signer here is a **key fingerprint**: the SHA-256 of the key blob, 64 lowercase hex — the digest `ssh-keygen -lf` prints as `SHA256:<base64>`, written in hex so that one form is legal in a filename, in an `allowed_signers` line and on a command line. `pubkey fingerprint` over a key line prints it. It is the only name this project gives a key: `init` stores keys as `multiproofs/pubkeys/<fingerprint>.pub`, signatures are `<file>.<fingerprint>.sig`, and `--signer` takes it. Nothing is derived from a file name or a key comment, and there is no flag to choose one — so a trust list that files mallory's key as `alice.pub` still renders mallory's fingerprint.

A `.pub` file's name is therefore decoration, and it is yours: rename a registered key with `mv`, or drop your own `alice.pub` into `multiproofs/pubkeys/` — the principal comes from the bytes inside either way (pinned by the test "a pubkey file name the trust list could never express still signs and verifies"). What such a name cannot do is *say* anything: `alice.pub` is not a claim that alice signed, and an invisible character makes one name read as another in a diff. That is why `init` does not invent one.

That is not the same as proving identity. A fingerprint names a key, not a person, and the trust list travels inside the very thing under examination. Binding a fingerprint to a person is the verifier's own step: compare it against one you hold from elsewhere. See "Verifying commit signatures" below.

Both hash file contents themselves, so neither constrains the repo: any git repo works, SHA-1 or SHA-256.

## Quick start

```nushell no-run
use nu-multiproof/

# Bootstrap multiproofs/ directory in your repo
nu-multiproof init

# Generate content manifest (SHA-256, git hash, IPFS CID v0)
nu-multiproof tree-hashes

# Derive the merkle root over the manifest and write multiproofs/tree-root.txt —
# the one artifact the two steps below sign and stamp, so it has to exist first.
# `seal` runs this itself; run it directly to seal under a key other than the
# repo's — see "Sealing under an explicit key" below.
nu-multiproof merkle write-root

# Sign the root statement with your SSH key. The key must already be registered
# in multiproofs/pubkeys/ — signing resolves the principal out of the trust list,
# so an unregistered key is refused rather than signing under a name nothing
# reading the artifact could resolve. `init --pubkey` is what registers one.
nu-multiproof ssh-sign sign multiproofs/tree-root.txt --key ~/.ssh/id_ed25519
# Verify signatures against bundled public keys
nu-multiproof ssh-sign verify multiproofs/tree-root.txt
# The principal a key signs under — what `merkle verify --signer` takes
open --raw ~/.ssh/id_ed25519.pub | nu-multiproof pubkey fingerprint
# The canonical pubkey bytes the fingerprint is taken over (type + base64 + \n)
open --raw ~/.ssh/id_ed25519.pub | nu-multiproof pubkey canonical

# Timestamp the signed statement via OpenTimestamps. Stamping after signing is
# what puts the signature in the bundle — `ots stamp` copies in the signatures
# sitting beside the file at stamp time; see "Bundle contract" below.
nu-multiproof ots stamp multiproofs/tree-root.txt
# Upgrade pending attestation to Bitcoin (hours/days later)
nu-multiproof ots upgrade multiproofs/ots-timestamps/tree-root.ABCD1234/tree-root.ots
# Inspect a timestamp
nu-multiproof ots info multiproofs/ots-timestamps/tree-root.ABCD1234/tree-root.ots
# Independently verify the Bitcoin anchor against real block headers
nu-multiproof ots verify multiproofs/ots-timestamps/tree-root.ABCD1234/tree-root.ots

# Extract a compact inclusion proof for one manifest row
nu-multiproof merkle prove README.md
# Verify it: fold to the signed root, check signatures, content, OTS status
nu-multiproof merkle verify multiproofs/inclusion-proofs/README.md.multiproof.json

# The whole pipeline in one step: manifest → merkle root → SSH signature →
# OTS stamp, then upgrade any pending stamp it finds. This is the command
# everything below is written in terms of.
nu-multiproof seal
nu-multiproof seal --repo path/to/other/repo   # seal a repo other than the CWD's
nu-multiproof seal --propose-commit            # leave the git commit in the prompt, unrun
nu-multiproof seal --no-content-anchor         # anchor the signatures only — see "Dating the endorsement"

# What the folder holds: one row per bundle, with the anchor state of the content
# it froze and of each signature beside it. Read-only, and not a verdict — see
# "Reading the folder" below.
nu-multiproof seal status

# The CID v0 of any bytes, standalone — the same one tree-hashes puts in content_cid
open --raw README.md | nu-multiproof cid-v0
```

### Sealing under an explicit key

The signing key comes from the target repo's `git config user.signingKey`; `seal` has no `--key` flag, because a repo's signing identity belongs in its config rather than in each invocation. To seal under a different key, run the steps `seal` wraps:

```nushell no-run
nu-multiproof init --pubkey ./otherkey.pub          # register it: sign refuses an unregistered key
nu-multiproof tree-hashes                           # regenerate the manifest
nu-multiproof merkle write-root                     # mint the root statement over it
nu-multiproof ssh-sign sign multiproofs/tree-root.txt --key ./otherkey
nu-multiproof ots stamp multiproofs/tree-root.txt   # optional — the time anchor
```

That is what `merkle write-root` is for on its own: it is the only way to mint `tree-root.txt` without `seal`, and therefore without `seal`'s key. What follows it is a plain `ssh-sign sign`, so a second signer is added the same way — sign the existing `tree-root.txt`, no re-rooting.

Two things this path does not buy. Staying offline is one: `seal --no-stamp` already skips the calendar post, so reach for the manual chain only for the key. The other is a repo elsewhere — `ssh-sign sign` takes `--pubkeys-dir` but no `--repo`, so run the chain from inside the target repo.

Its cost is state between steps: a manifest regenerated after the root was signed leaves a CSV no signature covers. `merkle verify` catches exactly that and reports it as `manifest_root` — see "Merkle inclusion proofs" below.

### Committing a seal

`seal` does not commit, and `--propose-commit` does not change that. It writes the commit into your prompt with `commandline edit` and stops there, so nothing runs until you read it, edit it and press enter. What it removes is the other failure: a seal landing under "wip", or spread over three commits, which makes the log useless for the one question it should answer — when was this root sealed.

```nushell no-run
nu-multiproof seal --propose-commit
```

The prompt then holds this, unrun:

```nushell no-run
let repo = "/path/to/repo"
let msg = "seal: multiproofs/ describes the tree at merkle root 9365958e

Root CID: QmPs9R2UGwGc5bDshLfVKvJp2pdntuGBaj2iR4kqcRQt4c
Merkle root: 9365958e2a87d29014a3ee71f502fc55bd50a1970220083092c325334e06efb0
Signed by: ed2386359d82cbeba2214f993392a15db8c99627173532f32f01934957799dc2
Bundle: multiproofs/ots-timestamps/tree-root.9A5D59BA
Anchors: content + 1 endorsement, pending until Bitcoin confirms"

git -C $repo add -- multiproofs
git -C $repo commit -m $msg
```

A block with variables rather than one long line, because the message is meant to be edited before it runs and a body escaped into `\n` inside a quoted argument is the one shape that cannot be edited comfortably. `$msg` gives the body real lines; `$repo` is used twice. Splitting `add` from `commit` costs nothing: Nushell throws on a non-zero external exit, so a failed `add` still stops before `commit`.

Three things about it are deliberate. `git -C <root>` because `seal --repo` may target another repo, and even locally the `multiproofs` pathspec resolves against the CWD, so a bare `git add` fails from any subdirectory (pinned by "git is aimed at the sealed repo rather than the current directory"). `add -- multiproofs` rather than the paths `seal` returned, because a seal also *deletes* inside that directory — a signature over bytes regen changed is cleared — and a deletion appears in no result field, so a proposal naming only written files would commit a folder git still holds a cleared signature for. And `Signed by` is the principal `seal` resolved from key material before signing, never a name read back off `<file>.<fingerprint>.sig` — the filename-as-identity shape this repo removed (pinned by "the signer is the principal passed in, not anything read off a filename").

Everything interpolated into the block is escaped with `to nuon` — nuon *is* Nushell's own string-literal syntax, so its serializer already owns the job of staying in step with the parser. A repo path is data and the block is handed to a prompt ready to run, so what is pinned is the escaping **at its use site**: a repo checked out to a directory holding a quote and a backslash is sealed, and the emitted block is executed for real, in "a repo root holding a quote and a backslash still commits". Testing the escaper alone is not enough — both calls to it could be replaced with raw interpolation and the rest of the suite stayed green.

What this does not do is sanitize for display. A control character in the path reaches the prompt raw, so a directory named with ANSI escapes could repaint the line you are meant to read before pressing enter. That is a deliberate limit, not an oversight: the guarantee is that the block *parses* as one command with one argument, never that it *renders* honestly. The repo root is a path you chose, not attacker-supplied input.

Outside a REPL `commandline edit` still writes the engine's repl buffer — it is harmless, not a no-op — and only the REPL reads that back, so the flag is inert in a script rather than an error (pinned by "asking for a commit proposal leaves the seal result untouched").

## Prerequisites

- [Nushell](https://www.nushell.sh/) — developed and tested on 0.114.1; the minimum supported version has not been established
- `git` (any repo)
- `ssh-keygen`, from OpenSSH — for signing, and also for **verifying**: `pubkey canonical` defers to `ssh-keygen` to decide what is a well-formed key, so anything that renders a trust list needs it. That includes `init`, `ssh-sign verify` and `merkle verify`. A missing binary is reported as a broken toolchain, never as a verdict about the artifact

### Testing

Tests use [nutest](https://github.com/vyadh/nutest). Clone it as a sibling directory:

```bash
git clone https://github.com/vyadh/nutest ../nutest
```

```nushell no-run
use toolkit.nu *
main test              # runs tests/; exits non-zero on any failure
main test --no-fail    # exit 0 even when tests fail
main test --network    # runs tests-network/ instead — reaches the internet, and
                       # one test writes a permanent public timestamp
```

Network tests are held out of the default run because of that permanent write, not because they are optional.

## Content manifest

`nu-multiproof tree-hashes` writes `multiproofs/tree-hashes.csv`: one row per git-tracked file, one per parent directory, and one for the repo root `.`. A file row names the same bytes three ways — `content_sha256` (raw bytes), `content_git` (git's blob object, from a temp index over the working tree, not from HEAD) and `content_cid` (IPFS CID v0). A directory row has no `content_sha256`, since a directory has no bytes of its own; its `content_git` is git's tree object and its `content_cid` the UnixFS directory. The `.` row carries the root CID alone. Rows under `multiproofs/` are excluded, so the manifest never describes its own proofs.

Beside the manifest, `tree-hashes` records which commit that manifest describes: `multiproofs/snapshot.txt`, one line — `multiproof-snapshot-v1 <commit>`. It is written **only when the tree it read equals HEAD**, and a dirty tree deletes any record an earlier run left, so a stale line cannot outlive the state it described. That condition is what makes the line checkable instead of a claim: rows under `multiproofs/` are excluded from the manifest, so the manifest of HEAD's tree and the manifest of a clean working tree are byte-identical — check out the commit it names, rebuild, and the merkle root must match (pinned by the test "the recorded commit rebuilds to the same merkle root in a fresh checkout"). Nothing signs it and nothing reads it: it is provenance for a person or a later tool, never an input to a verdict. Two bounds. A repo before its first commit has no HEAD to name, so no file appears — absence is the normal state, not an error. And the manifest is a function of the *checkout*, not of the commit: a checkout filter (`core.autocrlf`, `.gitattributes`, git-LFS) is machine configuration the commit does not carry, so two checkouts of one commit can hash differently. That fails safe — a verifier then says "does not match", never the reverse. The seal commit body carries the same commit through `--propose-commit`, and there alone it may read "plus uncommitted changes": a commit message is a human channel, so an unchecked claim is allowed in it.

Two ways to look at it without reading the CSV. `tree-hashes --echo` returns the table and writes nothing — including no snapshot record, since it saves no manifest for one to describe — so it is the safe one — use it to see what a seal would record. `tree-hashes root-cid` returns the `.` row's CID alone, but it is **not** read-only: it regenerates the manifest first, so running it after a seal can leave a CSV no signature covers, exactly the drift `merkle verify` reports as `manifest_root`.

CIDs are computed in-process, in Nushell — no `ipfs` daemon or CLI is involved, and there is only one manifest shape to sign. Content over 256 KiB is chunked and folded into a UnixFS DAG the same way the reference client does it, so `content_cid` is the CID `ipfs add` reports for that file, and the `.` row is the CID of the whole tracked tree. Reference: `nu-multiproof/_cid-helpers.nu`; conformance vectors in `tests/test_cid-v0.nu`, recorded from the reference client — single files from empty up to one full 262144-byte chunk, a multi-chunk file, a two-level DAG (175 chunks), a directory tree, and the directory at the HAMT threshold. The chunked and directory vectors were recorded with ipfs 0.42.0; the empty-directory CID is publicly known rather than recorded. What no vector covers is a file DAG deeper than two levels — 175 full branches, about 7.9 GB. The fold there is the same code, but nothing outside this repo pins it.

One limit, and it fails loudly rather than lying: IPFS switches a directory to a HAMT shard once its entries exceed 256 KiB by kubo's estimate (name length + 34 bytes per entry — about 6200 files with 8-character names in a single directory, and fewer as the names get longer). This builds basic directories only, so `tree-hashes` refuses such a directory instead of emitting a CID no IPFS client would reproduce.

The root CID names content, it does not publish it. Nothing here talks to IPFS, so the tree is retrievable through the network only if you add it yourself. Over a directory holding exactly the tracked files, `ipfs add -r --hidden --cid-version=0 --raw-leaves=false --hash=sha2-256 --chunker=size-262144` reproduces the `.` row (`--hidden` because `ipfs add` skips dotfiles otherwise).

## Merkle inclusion proofs

`multiproofs/tree-hashes.csv` is a flat manifest: signing it whole would mean that proving one file's inclusion requires keeping the entire CSV. The merkle layer fixes that. The CSV stays the authoritative catalogue, but `seal` also derives a binary merkle tree over its rows and signs/stamps only the one-line root statement (`multiproofs/tree-root.txt`). A consumer then holds one row plus ~log2(n) sibling hashes — for a million files, ~20 hashes instead of a million rows. (Git's own trees cannot do this job: they branch wide, so a path through them lists every sibling in each directory — it grows with directory width and leaks the neighbors' filenames.)

The root also authenticates the whole catalogue, indirectly: it is computed from every row, so anyone holding the full CSV can rebuild the tree and must land on the signed root — alter one row and the roots diverge. That is why `seal` itself no longer signs the CSV: earlier versions did during a transition, and git tag `pre-drop-manifest-sig` marks the last version that produced such a signature. `ssh-sign sign multiproofs/tree-hashes.csv` still works, and a signature over the manifest is cleared by exactly the same rule as one over the root statement — it survives a reseal that regenerates identical bytes, and goes when the bytes change (pinned by "a deliberate manifest signature survives an unchanged reseal"). One deliberate boundary: the root commits to the parsed row data, not the CSV's exact bytes (column order, quoting style) — leaf serialization uses parsed field values because CSV quoting is not canonical.

A consumer's full artifact set: the proof file (`merkle prove <filepath>`), `tree-root.txt`, a `.sig` over it, the signer's pubkey from `multiproofs/pubkeys/`, and — for the time anchors — the `tree-root.*` OTS bundle, which carries both (`<stem>.ots` dates the content, `<stem>.<ext>.<fingerprint>.ots` dates the endorsement; see "Dating the endorsement").

The trust list it checks against is, by default, the one inside the target — for a portable bundle, the bundle's own `multiproofs/pubkeys/`. A default `valid: true` therefore says the artifact set is internally consistent, not that the signer you expect endorsed it: anyone can fork the repo, `init` with their own key and re-`seal`. `--pubkeys-dir` points the check at a list you control, and `--signer <fingerprint>` narrows further to a valid signature from that one key instead of from any registered key. Because a principal is the key's own fingerprint, `--signer` is a statement about key material and holds even over the bundle's own list: a bundle can call its key files anything, and the rendered principal still comes from the bytes inside them, so it cannot make its key answer for yours (pinned by the test "a bundle cannot file one key under the fingerprint of another"). What a bundle *can* do is not carry the key at all, and a `--signer` the trust list holds no key for is an error, not `valid: false`: "alice did not sign this" is a claim, and without alice's key the verifier cannot make it (pinned by "signer with no matching key in the trusted dir is an error, not invalid"). Which fingerprints count is still a statement only the verifier can make — the same verifier-side policy described under "Verifying commit signatures" below.

`merkle verify` folds the proof to the signed root, checks the SSH signatures over the root statement, re-hashes the on-disk file against the proven `content_sha256` when present, and reports the OTS anchor as a status (`absent`/`pending`/`anchored` — a fresh seal stays pending until Bitcoin confirms, hours or days). A proof whose embedded root differs from the signed root is for a different seal and fails loudly rather than reporting invalid.

The content leg answers with a state, not a boolean, and **only `true` passes** — every other value blocks `valid`. A row whose commitment could not be checked must never read as one that checked out:

| `content_verified` | meaning |
|---|---|
| `true` | the bytes on disk match what the leaf attests |
| `false` | they do not — the file changed, or the proof describes different bytes |
| `"missing"` | nothing at that path on disk |
| `"symlink"` | a symlink where the catalogue describes a regular file (checked before existence, so a broken link does not read as missing) |
| `"outside"` | the path resolves out of the repo, through a symlinked parent |
| `"directory"` | a file row landing on a directory |
| `"unverifiable"` | the leaf carries no commitment at all — neither a `content_sha256` nor a `content_cid`, so there is nothing to re-derive |

When `multiproofs/tree-hashes.csv` is there, `merkle verify` also rebuilds the root from it and reports it as `manifest_root`; a value differing from the signed `root` blocks `valid`. The statement is a claim about that catalogue, and the two are written in separate steps — an interrupted `seal`, or a bare `tree-hashes` run afterwards, leaves a CSV no signature covers while old proofs still fold to the old statement. A portable bundle carries no CSV, so `manifest_root` is `null` there and nothing is cross-checked. (Pinned by the test "a manifest that no longer yields the signed root is caught".)

A proof of an **older seal** is still checkable in place with `--multiproofs-dir`: point it at a directory holding that seal's `tree-root.txt` and its `.sig` files (a CSV is optional, cross-checked when present), while `--repo` keeps naming the live content. The signed statement, its signatures and the manifest leg are read from the named directory; the trust list default and the OTS stamp discovery stay with `--repo` — a snapshot freezes statement and signatures, never keys, and the stamp archive is cross-seal with discovery by content hash. (Pinned by "a proof of an older seal verifies against that snapshot of the seal", "the manifest cross-check follows the multiproofs dir, not the repo", "a planted signature over another statement does not endorse the snapshot" and "an anchor in the live archive dates an older seal verified via its snapshot".)

### Verifying without the origin repo

The artifact set is portable. Lay it out in a plain directory — no git, no clone of the origin repo — mirroring the `multiproofs/` layout, and point `merkle verify` at it with `--repo`:

```
bundle/
  README.md                                # the proven file, at the leaf's filepath
                                           #   (a directory row: the whole subtree, at its filepath)
  multiproofs/tree-root.txt                # + its .<fingerprint>.sig alongside
  multiproofs/pubkeys/<fingerprint>.pub
  multiproofs/inclusion-proofs/<row>.multiproof.json
  multiproofs/ots-timestamps/tree-root.*/  # optional — without it `ots` reports `absent`;
                                           #   its <stem>.<ext>.<fingerprint>.ots dates the endorsement
```

```nushell no-run
nu-multiproof merkle verify bundle/multiproofs/inclusion-proofs/README.md.multiproof.json --repo bundle/ --bundle
```

The proof file belongs under `multiproofs/`, not at the bundle root. Everything under that prefix is excluded from the manifest and from the re-derivation, so a proof of the `.` row does not fold its own proof file into the CID it is checking. At the root it would, and the bundle would report itself as tampered.

This is a supported contract, pinned by a test — not an accident of path handling: an explicit `--repo` is taken as-is (no git required), and every lookup is layout-relative to it. One caveat: `seal`'s opportunistic OTS upgrade only walks the target repo's own `multiproofs/ots-timestamps/`, so a bundle's `pending` stamp stays pending until you run `ots upgrade` on it yourself.

A proof of a **directory row** (or of `.`) works the same way, with one extra thing in the bundle: the subtree itself, laid out under the row's `filepath`. A directory's `content_cid` commits to every entry under it, so it can only be re-derived from the files, and a compact proof cannot stand in for them. Away from the origin repo there is no git index to enumerate from, so `merkle verify` walks the bundle instead — dropping `multiproofs/` and `.git`, the two directories the manifest never covered and which sit *inside* the walked tree when the row is `.`. Dropping `.git` is what lets a bundle be a clone of the sealed repo, the most ordinary way one travels (pinned by "the root row of a bundle distributed as a git repo still verifies").

That walk trusts the bundle for the file list, and does not need to: the sealed `content_cid` is what checks the list. Under the proven row, a bundle that drops a file, adds one, or alters a byte folds to a different CID and is refused — pinned by "a non-git bundle carrying the sealed subtree verifies a directory row" (the same fixture verifying), "a bundle that drops a file from a proven directory is refused", "a bundle that adds a file under a proven directory is refused", and "a non-git bundle carrying the wrong bytes under a proven directory is refused". Files *outside* the proven row's subtree are not covered and never were: the walk is scoped to that subtree, so an unrelated file — or a stray symlink — beside it does not turn a genuine proof into a report of tampering. What git answers in a live worktree is a different question again, which files are untracked build output the seal never covered.

**Pass `--bundle` for an artifact someone sent you.** Without it, `merkle verify` takes the git arm whenever the target *is* a git repo root — and a sender can make that true. A `.git` costs nothing to ship, and one whose index lists exactly the sealed paths hands the sender the file set: the same bundle carrying an extra file under the proven directory answers `valid: true` with that `.git` present and `valid: false` without it. `--bundle` ignores any index the target carries and always walks, so the enumeration is the verifier's choice rather than the artifact's (pinned by "a bundle cannot hand itself the git arm by shipping its own index"). Distributing a bundle as a git repo is ordinary, so this is not an exotic shape. The flag is a no-op for file rows, which never consult git.

Which arm ran is reported as `content_enumeration` — `"git-index"` or `"walk"`, and `null` for a row that consulted no file set. The two readings of `content_verified: true` are different claims ("the tracked files are the sealed ones" versus "everything the sender shipped folds to the sealed CID"), so a consumer keying on `.valid` needs to see which one it got. The flag lets a verifier choose the arm; the field lets it check what it chose.

`content_verified: "unverifiable"` is therefore left for one case only: a row that commits to no content at all — no `content_sha256` and no `content_cid`. It still blocks `valid`, because a row whose only commitment cannot be checked must not read as one that was.

### Tree specification

Pinned exactly, so an independent implementation reproduces the root from the same CSV (reference: `nu-multiproof/_merkle-helpers.nu`, test vectors: `tests/test_merkle.nu`).

- **Leaves**: all CSV rows (directory rows and the `.` root-CID row included), sorted by `filepath` — byte-wise lexicographic over the UTF-8 path bytes, no locale, no Unicode normalization. Duplicate filepaths are a hard error.
- **Columns**: exactly the four below, no more and no fewer. A fifth column is refused rather than ignored — the leaf bytes would not say it was there, so two manifests differing only in a dropped column would share a root.
- **Leaf bytes**: the four parsed field values (RFC 4180 CSV parsing, not raw lines) joined with `\n`: `filepath \n content_sha256 \n content_git \n content_cid`.
- **Charset constraints** (make the `\n`-join injective; reject, never normalize): `filepath` is non-empty and contains no bytes < 0x20; `content_sha256` is empty or 64 lowercase hex; `content_git` is empty or 40/64 lowercase hex (SHA-1 or SHA-256 git repos); `content_cid` is empty or a base58btc CIDv0 (`Qm` + 44 chars).
- **Path containment**: `filepath` has no leading `/` and no `..` component. `verify` joins it onto the target directory and reads it, so either form would let a bundle prove a file it does not contain — or one belonging to the verifier. `git ls-files` emits neither, so nothing legitimate is refused. Bare `.` is legal on purpose: it is the root-CID row.
- **Symlinks**: refused, never followed. Following one would take `content_sha256` and `content_cid` from the target while `content_git` stays git's blob of the link string — one row describing two objects, and a link pointing outside the repo would pull foreign content into the catalogue. `tree-hashes` errors and names the offending paths.
- **Hashing** (RFC 6962 domain separation): leaf hash = `sha256(0x00 ++ leaf_bytes)`; inner node = `sha256(0x01 ++ left ++ right)` over the raw 32-byte child hashes.
- **Shape** (RFC 6962 MTH): split the leaf list at the largest power of two below n, recurse on both halves. No padding, no last-leaf duplication. n=1: root = the leaf hash. n=0: root = `sha256("")` = `e3b0c442…`.
- **Proof steps**: `side` names the **sibling**'s position, leaf-to-root order: `side: right` → `acc = sha256(0x01 ++ acc ++ sibling)`; `side: left` → the sibling goes first. Encoding is checked before folding: `hash` must be a JSON *string* of 64 lowercase hex (a number, or hex with any uppercase, is refused — not coerced), and `side` must be exactly `left` or `right`. This is the most common interop bug in merkle verifiers, so it fails loudly instead of folding something plausible.
- **Root statement**: exactly `multiproof-merkle-v1 <64 lowercase hex>` + one trailing `\n`. The statement form (not a bare hash) keeps the signature from being replayed in another hash-signing context.

## Origin proofs

This repository contains proofs of how it came to exist in [`multiproofs/origin-proofs/`](multiproofs/origin-proofs/). See that directory's README for the full story; in brief:

- **`tree-hashes.CCA016A8/`** — Bitcoin block 939896 timestamp of the extracted subtree (source repo snapshot), with SSH signature
- **`tree-hashes.93223B2F/`** — bridge stamp: first OTS made from inside this repo post-extraction, Bitcoin block 940583

These are archival artifacts. Ongoing operational timestamps live in [`multiproofs/ots-timestamps/`](multiproofs/ots-timestamps/).

### Bundle contract

An OTS bundle directory (`multiproofs/ots-timestamps/<stem>.<hash-prefix>/`) is self-contained provenance: every file needed to assert *"content C existed at time T, anchored to Bitcoin block B, and signer X endorsed C by time T2"* lives in the directory, with no reference to anything outside it. Read each anchor separately — a proof commits to the hash of one file and nothing else, so the snapshot's anchor dates C while a signature's anchor dates that endorsement. One seal moment is one bundle: `seal` stamps the root statement and every signature over it *into the same directory* (pinned by "seal puts the root statement, its signature and both anchors in one bundle"), so the two claims sit side by side instead of in two directories neither of which could make both. Under `--no-content-anchor` the same directory is minted from the same name and carries the same frozen copy, with no `<stem>.ots` in it (pinned by "seal --no-content-anchor dates every signature and leaves the content undated") — one bundle either way, so nothing that reads this tree needs a second layout.

- `<stem>.<ext>` — frozen content snapshot (the stamped file's bytes at stamp time)
- `<stem>.ots` — the timestamp over the snapshot's hash. A fresh `ots stamp` writes a *pending* calendar attestation here; `ots upgrade` replaces it in place with the Bitcoin-anchored one once a block confirms it, hours or days later. Until that upgrade runs, the bundle carries the content and the signature but not yet the anchor, so it cannot make the "at time T, in block B" half of the claim above
- `<stem>.<ext>.<fingerprint>.sig` — SSH signature over the snapshot, copied in at stamp time so it survives the next `seal` (which overwrites the live sig). Every signature sitting beside the stamped file is copied, the bare `<stem>.<ext>.sig` form included, so a bundle carries one per signer rather than one (pinned by the test "stamp snapshots every signature beside the file it stamps"). `seal` signs before it stamps, so its own bundles always carry at least its own (pinned by "seal puts the root statement, its signature and both anchors in one bundle")
- `<stem>.<ext>.<fingerprint>.ots` — the timestamp over *that signature's* hash, so the bundle dates the endorsement and not only the content. Same naming rule as `<stem>.ots` one level in: strip `.ots` and the sibling it proves is what remains. Written by `ots stamp <sig> --into <bundle>`, which joins an existing bundle instead of deriving a directory of its own (pinned by "stamp --into joins the named bundle instead of deriving one"). The bundle must already exist *as a real directory* — a typo would otherwise create a directory outside this grammar (pinned by "stamp refuses an --into bundle that does not exist"), and a regular file or a symlink to a directory both lose the proof after the digest is already posted (pinned by "stamp refuses an --into that exists but is not a real directory"). It also refuses to take a `<stem>.ots` name when that proof covers a *different file still in the bundle*, since two files can share a stem and only one can own the name (pinned by "stamp --into refuses to take the .ots name that another file proof holds"), or when the incumbent proof cannot be read at all, since an unplaceable proof cannot be shown safe to archive (pinned by "stamp --into refuses when the incumbent proof cannot be read"). What it does *not* refuse is a superseded proof of the same name: re-signing with a randomized key (ECDSA, ecdsa-sk) makes new signature bytes under the same `.sig`, so a second `seal` over unchanged content re-anchors that signature and archives the previous proof (pinned by "a second seal over unchanged content re-anchors the new signature")
- `<stem>.<YYYYmmdd-HHMMSS>-<8 hex of its own sha256>.ots` — a previous proof of the same content, archived by the re-stamp that replaced it. Same content, different nonce and calendar response, so it is an independent attestation worth keeping; the hash in the name makes the archive name collision-proof for two stamps in one second (pinned by the test "rapid re-stamps each keep their own proof")
- `<stem>.<YYYYmmdd-HHMMSS>-<8 hex of its own sha256>.ots`, **written by a failed stamp** — when `<stem>.ots` cannot be written (another stamp won the race), this run's assembled proof is parked beside it rather than dropped: the nonce binding it to this file exists only in that run. The name shape is identical to the archived form above, so the two are not distinguishable on disk — both are genuine proofs of the bundle's content, which is why `merkle verify` discovers proofs by content rather than by name. The command still exits non-zero and names the path

One more form is written **outside** any bundle, directly under `multiproofs/ots-timestamps/`:

- `<stem>.<hash-prefix>.rejected-<YYYYmmdd-HHMMSS>-<8 hex of its own sha256>.ots` — a calendar answer that did not parse into a readable proof. No bundle is created, and these bytes are deliberately not a proof; they are kept because the digest already reached the calendar and the nonce is unrecoverable otherwise. The reference `ots` CLI reads constructs this parser refuses (forks, for one), so recovery may still be possible from them (pinned by the test "rejected stamps in the same second each keep their nonce"). Under `--into` they go to the bundle's *parent*, for the same reason: a bundle is the one place bytes that are not a proof must not be mistaken for one (pinned by "a rejected response under --into lands outside the bundle", and for a relative `--into` by "a rejected response under a relative --into is still parked, not lost")

`seal` produces this layout automatically. The next `seal` regenerates `multiproofs/tree-hashes.csv` and re-signs `tree-root.txt` when its bytes changed — previous bundles remain intact because the frozen copy and its sig were already copied in. Each new seal produces one `tree-root.*` bundle holding the root statement, its signatures and an anchor for each: the manifest is neither signed nor stamped anymore, since the root statement is derived from every manifest row, so its signature and Bitcoin anchor cover the full CSV. Archival `tree-hashes.*` bundles (including `origin-proofs/`) stay valid as-is; the transition-era ones may also carry a CSV sig.

The bundles committed to this repo are history, not examples, and they show the layout arriving in stages. Every `.sig` in them now carries a fingerprint, but the older ones were named after a key *file* until they were renamed in place — one key was filed under two names (`maxim-uvarov2` and `id_ecdsa_sk_rk`) for the same ECDSA-SK key, which is the double identity the fingerprint principal exists to remove. Renaming changed nothing a verifier reads: a label is not part of the signed bytes, and the principal comes from key material via `find-principals`. Two things about them do not match the grammar above and cannot be fixed by a rename. The `origin-proofs/` bundles carry a signature over the **`.ots`** rather than over the frozen snapshot, added by hand after stamping — a shape `ots stamp` never writes, since it copies the signatures sitting beside the file it stamps. And only `tree-root.83089A30/` holds an endorsement anchor: the ten older bundles have none and cannot get one, because a stamp made today would date those July signatures to today and make the folder read as though they were dated when sealed.

### Reading the folder

`nu-multiproof seal status` reports every bundle in one table, so "is this sealed, and is it dated yet" needs no reading of directory names and no `ots info` by hand:

This repo's own output, with the `bundle` column shortened to its last path segment to fit (it is really repo-relative, `multiproofs/origin-proofs/tree-hashes.93223B2F` and so on):

```
╭────┬──────────────────────┬─────────────────┬─────────┬─────────────────┬─────────┬──────────╮
│  # │        bundle        │      file       │ current │     content     │ signers │ endorsed │
├────┼──────────────────────┼─────────────────┼─────────┼─────────────────┼─────────┼──────────┤
│  0 │ tree-hashes.93223B2F │ tree-hashes.csv │ false   │ anchored 940583 │       1 │ absent   │
│ …  │ …                    │ …               │ …       │ …               │       … │ …        │
│  8 │ tree-root.050186F7   │ tree-root.txt   │ false   │ anchored 958319 │       1 │ absent   │
│  9 │ tree-root.25A4101E   │ tree-root.txt   │ false   │ anchored 958319 │       1 │ absent   │
│ 10 │ tree-root.83089A30   │ tree-root.txt   │ true    │ pending         │       1 │ pending  │
╰────┴──────────────────────┴─────────────────┴─────────┴─────────────────┴─────────┴──────────╯
```

`current` is a byte compare against the live artifact of that name under `multiproofs/`, which is the only thing separating the seal in force from the archive — they look alike on disk (pinned by "seal status marks only the bundle whose snapshot is the live artifact"). It is `null`, not `false`, when no live artifact shares the name: `false` says "a later seal superseded this", and a bundle over some other file was never in that race (pinned by "seal status reports current as null when no live artifact shares the name"). `content` and `endorsed` are `absent`, `pending`, or `anchored <height>`, and `endorsed` carries one per signature in the bundle. The number is the Bitcoin block the proof binds to — the only time an `.ots` carries, since a block's wall-clock time lives in its header and no proof holds one; a date therefore needs `ots verify`, which fetches headers and cross-checks explorers, so `status` stays offline and reports the height (pinned by "seal status reports the block height an anchor binds to"). Two seals can share a block, as rows 8 and 9 do: a calendar aggregates every digest it receives into one merkle tree per transaction.

Bundles are found by the proofs they hold rather than by a name pattern, across the whole `multiproofs/` tree — so archival subtrees like `origin-proofs/` appear too, which the operational scan `merkle verify` uses does not cover (pinned by "seal status reports a bundle in an archival subtree, not just ots-timestamps"). Real directories only, so a bundle behind a symlink is not listed (pinned by "seal status does not list a bundle behind a symlinked directory"), and a parked rejected calendar answer is skipped rather than reported as a broken proof (pinned by "seal status says nothing about a parked rejected calendar answer"). The snapshot a row names is likewise the file a proof in that bundle *commits to*, so a stray file dropped into a bundle is not mistaken for its content; where a bundle holds two stamped non-signature files, the one it is *named* after wins, since that hash is the bundle's reason to exist (pinned by "seal status names the file the bundle is keyed by when it holds two"). Symlinks inside a bundle are skipped rather than followed — the bytes behind a link are not the ones the name describes, and following one used to abort the whole report (pinned by "seal status reports a bundle holding symlinks instead of failing").

`endorsed` is empty when `signers` is 0, and otherwise carries one entry per signature in sorted signature-file order (pinned by "seal status reports one endorsement entry per signature"). A bundle whose only stamped content is a signature reads `file: null`, `content: absent`, `signers: 1` and a dated `endorsed`: it carries an endorsement and its date but no content snapshot, and `signers` is what tells it apart from a bundle holding nothing (pinned by "seal status reports a signature-only bundle as an undated-content endorsement"). Two layouts read this way — the one `seal` wrote before the two anchors shared a directory, which has no frozen copy at all, and what `seal --no-content-anchor` writes today, which does have one but no proof over it. `file` names the snapshot a proof in the bundle commits to, so an unstamped frozen copy is not named there.

It is **not** a verdict. No signature is checked, so `signers` counts signature *files* and the report never says a signature is valid or who made it: a name on disk is not evidence of a signer, which is the whole reason a principal is a key's fingerprint. Use `ssh-sign verify` or `merkle verify` for that.

### Dating the endorsement

An OTS proof commits to the hash of one file, so "when did this content exist" and "when was it endorsed" are two claims needing two stamps. An SSH signature carries no timestamp field, so with only the root stamped, a `.sig` made today drops into a year-old bundle and nothing on disk contradicts it.

`seal` step 4 therefore stamps `tree-root.txt` **and every signature beside it**, all into the root statement's own bundle:

| stamp commits to | claim | reported as |
| --- | --- | --- |
| sha256 of `tree-root.txt` | the content existed by T | `ots` |
| sha256 of a `.sig` over it | that endorsement existed by T | one row in `endorsements` |

Both stay checkable by hashing a file you already hold — no key material for either. `merkle verify` returns one `endorsements` row per signature that verified, `{signer, status, ots, height}`, with the same `absent | pending | anchored` values as `ots`; `height` is the Bitcoin block and is null while pending. Where several anchors of the same bytes exist, the reported one is the **lowest** block: the claim is "existed no later than T", so the earliest anchor is the strongest and the rest follow from it (pinned by "seal status reports the earliest anchor when a bundle holds several"). A stamp is matched to its signer by hashing the signature file, never by a `.sig` name, and a signature that did not verify gets no row at all: dating bytes says when they existed, never that they endorse anything. A real signature over this root by a key the trust list does not hold is exactly that case — cryptographically fine, stamped, and still not an endorsement anyone here trusts (pinned by "a dated signature by an unregistered key is not an endorsement").

Because the loop runs over `sig-files-for`, a **co-signer is dated for free**: sign `tree-root.txt` out of band with a registered key, and the next `seal` stamps that signature alongside its own (pinned by "each signature gets its own dated endorsement").

Why two stamps and not one object naming both files by digest: an OTS calendar aggregates every digest it receives into one merkle tree per Bitcoin transaction, so the second post costs nothing on-chain, and such an object would only re-implement that batching a layer up — while adding an artifact, a grammar, a parser, and a per-signer limit the loop above does not have. Why not stamp the signature *alone*, which dates the content transitively: it makes the most durable claim depend on the most fragile one. Content-time would stop being a bare hash compare and start needing the pubkey, `ssh-keygen`, and a key type OpenSSH still reads — three things that can rot where a hash cannot, so a bundle that keeps a good key-free content anchor today would then have none.

`seal --no-content-anchor` takes that trade knowingly: it skips the root statement's stamp and anchors the signatures only, so the seal moment makes one claim instead of two. Why the option exists at all: a bundle carrying an anchor over `tree-root.txt` **and** one over a signature over it does not say which one dates the statement, what it means when they differ (content in block 100, endorsement in block 200), or whether verification needs both, either or neither. Nothing in the bundle answers that — on disk neither anchor is derived from the other — so every reader decides for itself, plausibly and differently, and both readings verify green, so nothing corrects the drift. A caller whose load-bearing claim is "S endorsed this by block N" — nu-cybergraph, where a link *is* an assertion by a signer — removes those three questions by always passing the flag, exposing no option of its own. The default does not move, because the paragraph above is real: an archive that must stay checkable without key material wants the content anchor. It is not a cost in calendar traffic either way, since a calendar batches every digest into one merkle tree per Bitcoin transaction — the second post is free, and dropping it saves nothing on-chain and almost nothing on disk. What the readers then say: `merkle verify` reports `ots: absent`, and `seal status` reports the bundle as `file: null`, `content: absent`, `signers: 1` with a dated `endorsed` (pinned by "seal status reports a --no-content-anchor seal as an undated-content endorsement"). `--no-stamp` and `--no-content-anchor` are refused together — one skips step 4, the other runs it over the signatures only (pinned by "seal refuses --no-stamp together with --no-content-anchor, before touching anything").

Worth having when a signature must outlive its key: after a compromise and revocation at time R, only a signature datable before R still means anything, and the same argument covers key rotation across a long archive. It also settles which of several co-signers endorsed first. For dating content alone — prior art, ordering two seals, proving a snapshot falls inside a retention window — the root's own stamp already answers, and the signature stamps add nothing.

One direction this does *not* give: OTS bounds a time from above only ("no later than T"), never from below. A lower bound has to come from inside the signed bytes — some recent unpredictable value the signer could not have known earlier.

The two `origin-proofs/` bundles do the reverse — a signature over the `.ots` rather than a stamp over the signature (see the note above). A signature over a proof adds no time, since the proof's authority is the chain; read them as history.

## Verifying a timestamp

`ots info` only echoes the block height the calendar server reported, and `ots upgrade` splices that height into the file after checking that it parses — neither checks it against Bitcoin. `ots verify` does. It does not trust the calendar at all:

1. **Looks the block height up on independent explorers** (`mempool.space` and `blockstream.info` by default) and requires every explorer that answers to agree on the block hash. This is the one thing it trusts a third party for: the height → hash mapping. Fewer than `--min-sources` explorers answering (default 2) is refused, not answered: with a single responder there is no cross-check at all, and that responder would choose both the block hash and the `block_time` this reports as the timestamp — the one claim the whole system exists to make. Pass `--min-sources 1` to rest on one source deliberately.
2. **Fetches the raw 80-byte block header** and recomputes two things locally — the double-SHA256 block hash (it must equal the hash the explorers agreed on) and the merkle-root binding (the header must commit to the exact value the proof's operations replay to). Read what that does and does not rule out: it does not check the work behind the header. `bits` is read out of the very header under examination, so "the hash meets its own target" proves nothing; a floor at mainnet's `powLimit` used to sit here and bought only ~2^32 hashes, minutes on a GPU, against an attacker who already controls every explorer that answered. A real bound needs the difficulty expected at that height, or a pinned block hash, and neither the proof nor the explorer answer carries data to check that against. So step 1 — independent explorers agreeing on the height → hash mapping — is the whole defence, and step 2 only proves the header the explorer served is the block it named. (Pinned by the test "check-block-header does not bound the work behind a header".)

```nushell no-run
use nu-multiproof/
# verify the anchor; --file also confirms the proof commits to that content
nu-multiproof ots verify multiproofs/origin-proofs/tree-hashes.CCA016A8/tree-hashes.ots --file multiproofs/origin-proofs/tree-hashes.CCA016A8/tree-hashes.csv
```

Pass `--sources` to cross-check against different explorers. It replaces the default pair rather than adding to it, so name every explorer you want asked. A pending (not-yet-confirmed) proof is rejected with a pointer to `ots upgrade`.

## Verifying commit signatures

Signing here is occasional rather than policy: agent-made commits carry no signature, and the hand-signed ones are scattered through the log, so `git log --show-signature` prints nothing for most of it. `ab03ade` ("revoke claude-code signing key") is one signed commit to try the recipe on. The recipe stays here because `multiproofs/pubkeys/` is exactly what an `allowed_signers` file is rendered from.

Verifying an SSH-signed commit involves two distinct checks:

1. **Cryptographic validity** — does the signature mathematically match the commit bytes under some public key? Key-agnostic, no trust required.
2. **Trust** — is that public key one *you* choose to recognize as a valid signer? Verifier-side policy.

Git conflates them: it refuses to verify SSH signatures unless `gpg.ssh.allowedSignersFile` is configured and points to an existing file. That file maps principals → keys → namespaces; it is your **local trust list**, not part of any commit. Setting it is a statement *you* make about which keys you trust — the repo cannot make it for you.

`multiproofs/pubkeys/` is this project's source of truth for who can sign. Nothing here writes the trust file for you: that file *is* your statement about which keys you accept, so building it is your step, not the repo's. The format is one line per key — `<principals> namespaces="git" <keytype> <base64>`. The `*` principal below is collective trust: the key is in this project's list, with no personal identity attached to it.

### One-shot inspection

`git -c key=value` overrides config for a single invocation, no persisted state:

```nushell no-run
let signers = "/tmp/nu-multiproof-signers"
ls --all multiproofs/pubkeys | get name | where ($it | path parse | get extension) == "pub" | each {|f| $"* namespaces=\"git\" (open --raw $f | split row --regex '\s+' | first 2 | str join ' ')" } | str join "\n" | save --force $signers
git -c $"gpg.ssh.allowedSignersFile=($signers)" log --format='%h %G? %an %s'   # G = good, N = unsigned
git -c $"gpg.ssh.allowedSignersFile=($signers)" log --show-signature -1 ab03ade
```

The first command is where to start: `%G?` marks every commit `G` or `N`, so it shows both that the trust list resolves and which commits it has anything to say about. `--show-signature -1` on an unsigned commit prints no signature line at all.

`first 2` keeps the key type and the base64 blob and drops the trailing comment (`alice@laptop`) — it is not part of the trust statement and differs per machine.

### Per-clone setup

For repeated inspection, write the same file inside this clone's `.git/` and point its **local** git config at it:

```nushell no-run
let signers = $"(git rev-parse --git-dir | str trim)/allowed_signers"
ls --all multiproofs/pubkeys | get name | where ($it | path parse | get extension) == "pub" | each {|f| $"* namespaces=\"git\" (open --raw $f | split row --regex '\s+' | first 2 | str join ' ')" } | str join "\n" | save --force $signers
git config gpg.ssh.allowedSignersFile $signers
```

`.git/config` lives inside this clone's `.git/` directory — it is not tracked, not pushed, not shared with collaborators. Plain `git log --show-signature` now resolves cleanly. Re-run the render after any change to `multiproofs/pubkeys/`.

### Reading the output

```
Good "git" signature for * with ECDSA-SK key SHA256:7SOGNZ2C…
```

- `Good` — both checks above passed.
- `for *` — the matched principal is the `*` you wrote into the file: confirms the key is in the project's trust list, but does not attach a personal identity. This is the appropriate trust statement for a project's tracked signers — collective trust, not individual identification.

One caveat about where the keys come from: `multiproofs/pubkeys/` travels inside the repo under examination, so rendering the trust file from it and then verifying that repo's commits proves the repo agrees with itself. Anyone can fork, add their own key and re-sign. To make it an identity check, compare the fingerprint git reports against one you hold from elsewhere — the same verifier-side step `merkle verify --pubkeys-dir` exists for.

## License

MIT
