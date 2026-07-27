# nu-multiproof

Proof of concept: Composable cryptographic proofs for git repositories, written in Nushell. No external dependencies beyond `git` and `ssh-keygen` — network calls use Nushell's built-in `http`.

🚧 The code in this repo was generated via `claude code`, is barely tested, and should not be considered secure.

## What you can prove

| Claim | Proof type | Mechanism |
|-------|-----------|-----------|
| **This content existed at a specific time** | OpenTimestamps | Hash chain anchored to a Bitcoin block header |
| **This file was in the catalogued snapshot** | Merkle inclusion proof | RFC 6962-style binary tree over the manifest rows; one signed 32-byte root verifies a proof of ~log2(n) hashes |

Each proof type is independent. Use either or both.

`ssh-sign` is not a third claim — it is the signing step under both. It signs a file with an SSH key, and verifies every `.sig` beside a file against the keys in `multiproofs/pubkeys/`, separating "content changed" from "key not registered". `seal` uses it to sign the root statement and `merkle verify` to check that signature. It also runs standalone on any file.

Neither proves identity. A signer name here is the filename of a `.pub` in `multiproofs/pubkeys/` — chosen by whoever committed that key, and travelling inside the very thing under examination. Binding a key to a person is the verifier's own step: compare the fingerprint against a list you hold. See "Verifying commit signatures" below.

Both hash file contents themselves, so neither constrains the repo: any git repo works, SHA-1 or SHA-256.

## Quick start

```nushell no-run
use nu-multiproof/

# Bootstrap multiproofs/ directory in your repo
nu-multiproof init

# Generate content manifest (SHA-256, git hash, IPFS CID v0)
nu-multiproof tree-hashes

# Timestamp a file via OpenTimestamps
nu-multiproof ots stamp multiproofs/tree-root.txt
# Upgrade pending attestation to Bitcoin (hours/days later)
nu-multiproof ots upgrade multiproofs/ots-timestamps/tree-root.ABCD1234/tree-root.ots
# Inspect a timestamp
nu-multiproof ots info tree-root.ots
# Independently verify the Bitcoin anchor against real block headers
nu-multiproof ots verify multiproofs/ots-timestamps/tree-root.ABCD1234/tree-root.ots

# Sign a file with your SSH key
nu-multiproof ssh-sign sign multiproofs/tree-root.txt --key ~/.ssh/id_ed25519
# Verify signatures against bundled public keys
nu-multiproof ssh-sign verify multiproofs/tree-root.txt

# Derive the merkle root over the manifest and write multiproofs/tree-root.txt (seal does this automatically)
nu-multiproof merkle write-root
# Extract a compact inclusion proof for one manifest row
nu-multiproof merkle prove README.md
# Verify it: fold to the signed root, check signatures, content, OTS status
nu-multiproof merkle verify multiproofs/inclusion-proofs/README.md.multiproof.json
```

## Prerequisites

- [Nushell](https://www.nushell.sh/) — developed and tested on 0.114.1; the minimum supported version has not been established
- `git` (any repo)
- `ssh-keygen` (for SSH signing)

### Testing

Tests use [nutest](https://github.com/vyadh/nutest). Clone it as a sibling directory:

```bash
git clone https://github.com/vyadh/nutest ../nutest
```

```nushell no-run
use toolkit.nu *; main test
```

## Content manifest

`nu-multiproof tree-hashes` writes `multiproofs/tree-hashes.csv`: one row per git-tracked file, one per parent directory, and one for the repo root `.`. A file row names the same bytes three ways — `content_sha256` (raw bytes), `content_git` (git's blob object, from a temp index over the working tree, not from HEAD) and `content_cid` (IPFS CID v0). A directory row has no `content_sha256`, since a directory has no bytes of its own; its `content_git` is git's tree object and its `content_cid` the UnixFS directory. The `.` row carries the root CID alone. Rows under `multiproofs/` are excluded, so the manifest never describes its own proofs.

CIDs are computed in-process, in Nushell — no `ipfs` daemon or CLI is involved, and there is only one manifest shape to sign. Content over 256 KiB is chunked and folded into a UnixFS DAG the same way the reference client does it, so `content_cid` is the CID `ipfs add` reports for that file, at any size, and the `.` row is the CID of the whole tracked tree. Reference: `nu-multiproof/_cid-helpers.nu`; conformance vectors recorded from ipfs 0.42.0 in `tests/test_cid-v0.nu`, covering a single chunk, a multi-chunk file, a two-level DAG (175 chunks), a directory tree and the empty directory.

One limit, and it fails loudly rather than lying: IPFS switches a directory to a HAMT shard once its entries exceed 256 KiB by kubo's estimate (name length + 34 bytes per entry — roughly 5900 short-named files in a single directory). This builds basic directories only, so `tree-hashes` refuses such a directory instead of emitting a CID no IPFS client would reproduce.

The root CID names content, it does not publish it. Nothing here talks to IPFS, so the tree is retrievable through the network only if you add it yourself. Over a directory holding exactly the tracked files, `ipfs add -r --hidden --cid-version=0 --raw-leaves=false --hash=sha2-256 --chunker=size-262144` reproduces the `.` row (`--hidden` because `ipfs add` skips dotfiles otherwise).

## Merkle inclusion proofs

`multiproofs/tree-hashes.csv` is a flat manifest: signing it whole would mean that proving one file's inclusion requires keeping the entire CSV. The merkle layer fixes that. The CSV stays the authoritative catalogue, but `seal` also derives a binary merkle tree over its rows and signs/stamps only the one-line root statement (`multiproofs/tree-root.txt`). A consumer then holds one row plus ~log2(n) sibling hashes — for a million files, ~20 hashes instead of a million rows. (Git's own trees cannot do this job: they branch wide, so a path through them lists every sibling in each directory — it grows with directory width and leaks the neighbors' filenames.)

The root also authenticates the whole catalogue, indirectly: it is computed from every row, so anyone holding the full CSV can rebuild the tree and must land on the signed root — alter one row and the roots diverge. That is why `seal` itself no longer signs the CSV: earlier versions did during a transition, and git tag `pre-drop-manifest-sig` marks the last version that produced such a signature. `ssh-sign sign multiproofs/tree-hashes.csv` still works, and a signature over the manifest is cleared by exactly the same rule as one over the root statement — it survives a reseal that regenerates identical bytes, and goes when the bytes change (pinned by "a deliberate manifest signature survives an unchanged reseal"). One deliberate boundary: the root commits to the parsed row data, not the CSV's exact bytes (column order, quoting style) — leaf serialization uses parsed field values because CSV quoting is not canonical.

A consumer's full artifact set: the proof file (`merkle prove <filepath>`), `tree-root.txt`, a `.sig` over it, the signer's pubkey from `multiproofs/pubkeys/`, and — for the time anchor — the `tree-root.*` OTS bundle.

The trust list it checks against is, by default, the one inside the target — for a portable bundle, the bundle's own `multiproofs/pubkeys/`. A default `valid: true` therefore says the artifact set is internally consistent, not that the signer you expect endorsed it: anyone can fork the repo, `init` with their own key and re-`seal`. `--pubkeys-dir` points the check at a list you control, and `--signer <name>` narrows that further to a valid signature from that principal instead of from any registered key. A principal is only the *stem of a `.pub` filename*, so `--signer` needs `--pubkeys-dir` and is refused without it: asked over the bundle's own list it would mean no more than "a file named `<name>.pub` signed this", and mallory's key copied in as `alice.pub` answered `alice: valid` (pinned by the test "signer flag against a bundle-supplied trust list is refused, not answered"). A `--signer` your own list holds no key for is an error too, not `valid: false`: "alice did not sign this" is a claim, and without alice's key the verifier cannot make it (pinned by "signer with no matching key in the trusted dir is an error, not invalid"). Which keys count is a statement only the verifier can make — the same verifier-side policy described under "Verifying commit signatures" below.

`merkle verify` folds the proof to the signed root, checks the SSH signatures over the root statement, re-hashes the on-disk file against the proven `content_sha256` when present, and reports the OTS anchor as a status (`absent`/`pending`/`anchored` — a fresh seal stays pending until Bitcoin confirms, hours or days). A proof whose embedded root differs from the signed root is for a different seal and fails loudly rather than reporting invalid.

When `multiproofs/tree-hashes.csv` is there, `merkle verify` also rebuilds the root from it and reports it as `manifest_root`; a value differing from the signed `root` blocks `valid`. The statement is a claim about that catalogue, and the two are written in separate steps — an interrupted `seal`, or a bare `tree-hashes` run afterwards, leaves a CSV no signature covers while old proofs still fold to the old statement. A portable bundle carries no CSV, so `manifest_root` is `null` there and nothing is cross-checked. (Pinned by the test "a manifest that no longer yields the signed root is caught".)

### Verifying without the origin repo

The artifact set is portable. Lay it out in a plain directory — no git, no clone of the origin repo — mirroring the `multiproofs/` layout, and point `merkle verify` at it with `--repo`:

```
bundle/
  README.md                                # the proven file, at the leaf's filepath
  multiproofs/tree-root.txt                # + its .<signer>.sig alongside
  multiproofs/pubkeys/<signer>.pub
  multiproofs/ots-timestamps/tree-root.*/  # optional — without it OTS reports `absent`
```

```nushell no-run
nu-multiproof merkle verify bundle/proof.multiproof.json --repo bundle/
```

This is a supported contract, pinned by a test — not an accident of path handling: an explicit `--repo` is taken as-is (no git required), and every lookup is layout-relative to it. One caveat: `seal`'s opportunistic OTS upgrade only walks the target repo's own `multiproofs/ots-timestamps/`, so a bundle's `pending` stamp stays pending until you run `ots upgrade` on it yourself.

A proof of a **directory row** (or of `.`) is the exception: it needs a git repo. A directory's `content_cid` commits to every tracked entry under it, so re-deriving it means walking the tracked tree the way `tree-hashes` did — a plain bundle has no such tree. There `content_verified` is `"unverifiable"` and `valid` is `false`, because a row whose only commitment cannot be checked must not read as one that was. File rows are unaffected. (Pinned by the test "a directory row in a non-git bundle reports unverifiable, not valid".)

### Tree specification

Pinned exactly, so an independent implementation reproduces the root from the same CSV (reference: `nu-multiproof/_merkle-helpers.nu`, test vectors: `tests/test_merkle.nu`).

- **Leaves**: all CSV rows (directory rows and the `.` root-CID row included), sorted by `filepath` — byte-wise lexicographic over the UTF-8 path bytes, no locale, no Unicode normalization. Duplicate filepaths are a hard error.
- **Leaf bytes**: the four parsed field values (RFC 4180 CSV parsing, not raw lines) joined with `\n`: `filepath \n content_sha256 \n content_git \n content_cid`.
- **Charset constraints** (make the `\n`-join injective; reject, never normalize): `filepath` contains no bytes < 0x20; `content_sha256` is empty or 64 lowercase hex; `content_git` is empty or 40/64 lowercase hex (SHA-1 or SHA-256 git repos); `content_cid` is empty or a base58btc CIDv0 (`Qm` + 44 chars).
- **Symlinks**: refused, never followed. Following one would take `content_sha256` and `content_cid` from the target while `content_git` stays git's blob of the link string — one row describing two objects, and a link pointing outside the repo would pull foreign content into the catalogue. `tree-hashes` errors and names the offending paths.
- **Hashing** (RFC 6962 domain separation): leaf hash = `sha256(0x00 ++ leaf_bytes)`; inner node = `sha256(0x01 ++ left ++ right)` over the raw 32-byte child hashes.
- **Shape** (RFC 6962 MTH): split the leaf list at the largest power of two below n, recurse on both halves. No padding, no last-leaf duplication. n=1: root = the leaf hash. n=0: root = `sha256("")` = `e3b0c442…`.
- **Proof steps**: `side` names the **sibling**'s position, leaf-to-root order: `side: right` → `acc = sha256(0x01 ++ acc ++ sibling)`; `side: left` → the sibling goes first.
- **Root statement**: exactly `multiproof-merkle-v1 <64 lowercase hex>` + one trailing `\n`. The statement form (not a bare hash) keeps the signature from being replayed in another hash-signing context.

## Origin proofs

This repository contains proofs of how it came to exist in [`multiproofs/origin-proofs/`](multiproofs/origin-proofs/). See that directory's README for the full story; in brief:

- **`tree-hashes.CCA016A8/`** — Bitcoin block 939896 timestamp of the extracted subtree (source repo snapshot), with SSH signature
- **`tree-hashes.93223B2F/`** — bridge stamp: first OTS made from inside this repo post-extraction, Bitcoin block 940583

These are archival artifacts. Ongoing operational timestamps live in [`multiproofs/ots-timestamps/`](multiproofs/ots-timestamps/).

### Bundle contract

An OTS bundle directory (`multiproofs/ots-timestamps/<stem>.<hash-prefix>/`) is self-contained provenance: every file needed to assert *"signer X endorsed content C at time T, anchored to Bitcoin block B"* lives in the directory, with no reference to anything outside it.

- `<stem>.<ext>` — frozen content snapshot (the stamped file's bytes at stamp time)
- `<stem>.ots` — Bitcoin-anchored timestamp over the snapshot's hash
- `<stem>.<ext>.<signer>.sig` — SSH signature over the snapshot, copied in at stamp time so it survives the next `seal` (which overwrites the live sig). Every signature sitting beside the stamped file is copied, the bare `<stem>.<ext>.sig` form included, so a bundle carries one per signer rather than one (pinned by the test "stamp snapshots every signature beside the file it stamps"). `seal` signs before it stamps, so its own bundles always carry at least its own (pinned by "seal stamps the root statement into the target repo and bundles its signature")
- `<stem>.<YYYYmmdd-HHMMSS>-<8 hex of its own sha256>.ots` — a previous proof of the same content, archived by the re-stamp that replaced it. Same content, different nonce and calendar response, so it is an independent attestation worth keeping; the hash in the name makes the archive name collision-proof for two stamps in one second (pinned by the test "rapid re-stamps each keep their own proof")

`seal` produces this layout automatically. The next `seal` regenerates `multiproofs/tree-hashes.csv` and re-signs `tree-root.txt` when its bytes changed — previous bundles remain intact because the frozen copy and its sig were already copied in. New seals produce only `tree-root.*` bundles: the manifest is neither signed nor stamped anymore, since the root statement is derived from every manifest row, so its signature and Bitcoin anchor cover the full CSV. Archival `tree-hashes.*` bundles (including `origin-proofs/`) stay valid as-is; the transition-era ones may also carry a CSV sig.

## Verifying a timestamp

`ots info` and `ots upgrade` only echo the block height the calendar server reported — nothing checks it against Bitcoin. `ots verify` does. It does not trust the calendar at all:

1. **Looks the block height up on independent explorers** (`mempool.space` and `blockstream.info` by default) and requires every explorer that answers to agree on the block hash. This is the one thing it trusts a third party for: the height → hash mapping. Fewer than `--min-sources` explorers answering (default 2) is refused, not answered: with a single responder there is no cross-check at all, and that responder would choose both the block hash and the `block_time` this reports as the timestamp — the one claim the whole system exists to make. Pass `--min-sources 1` to rest on one source deliberately.
2. **Fetches the raw 80-byte block header** and recomputes two things locally — the double-SHA256 block hash (it must equal the hash the explorers agreed on) and the merkle-root binding (the header must commit to the exact value the proof's operations replay to). Read what that does and does not rule out: it does not check the work behind the header. `bits` is read out of the very header under examination, so "the hash meets its own target" proves nothing; a floor at mainnet's `powLimit` used to sit here and bought only ~2^32 hashes, minutes on a GPU, against an attacker who already controls every explorer that answered. A real bound needs the difficulty expected at that height, or a pinned block hash, and neither the proof nor the explorer answer carries data to check that against. So step 1 — independent explorers agreeing on the height → hash mapping — is the whole defence, and step 2 only proves the header the explorer served is the block it named. (Pinned by the test "check-block-header does not bound the work behind a header".)

```nushell no-run
use nu-multiproof/
# verify the anchor; --file also confirms the proof commits to that content
nu-multiproof ots verify multiproofs/origin-proofs/tree-hashes.CCA016A8/tree-hashes.ots --file multiproofs/origin-proofs/tree-hashes.CCA016A8/tree-hashes.csv
```

Pass `--sources` to cross-check against different or additional explorers. A pending (not-yet-confirmed) proof is rejected with a pointer to `ots upgrade`.

## Verifying commit signatures

Commits in this repo are SSH-signed. Verifying an SSH-signed commit involves two distinct checks:

1. **Cryptographic validity** — does the signature mathematically match the commit bytes under some public key? Key-agnostic, no trust required.
2. **Trust** — is that public key one *you* choose to recognize as a valid signer? Verifier-side policy.

Git conflates them: it refuses to verify SSH signatures unless `gpg.ssh.allowedSignersFile` is configured and points to an existing file. That file maps principals → keys → namespaces; it is your **local trust list**, not part of any commit. Setting it is a statement *you* make about which keys you trust — the repo cannot make it for you.

`multiproofs/pubkeys/` is this project's source of truth for who can sign. Nothing here writes the trust file for you: that file *is* your statement about which keys you accept, so building it is your step, not the repo's. The format is one line per key — `<principals> namespaces="git" <keytype> <base64>`. The `*` principal below is collective trust: the key is in this project's list, with no personal identity attached to it.

### One-shot inspection

`git -c key=value` overrides config for a single invocation, no persisted state:

```nushell no-run
let signers = "/tmp/nu-multiproof-signers"
ls --all multiproofs/pubkeys | get name | where ($it | path parse | get extension) == "pub" | each {|f| $"* namespaces=\"git\" (open --raw $f | split row --regex '\s+' | first 2 | str join ' ')" } | str join "\n" | save --force $signers
git -c $"gpg.ssh.allowedSignersFile=($signers)" log --show-signature -1
```

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
