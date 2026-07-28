# nu-multiproof

Proof of concept: Composable cryptographic proofs for git repositories, written in Nushell. No external dependencies beyond `git`, `ssh-keygen` and `chmod` — network calls use Nushell's built-in `http`.

🚧 The code in this repo was generated via `claude code` and has never been reviewed by an outside cryptographer — do not rely on it for anything that matters. It is not untested: 192 tests, every verifier guard mutation-checked, and the hostile artifacts are hand-built rather than produced by this repo's own builder. That establishes the guards do something, not that the design is sound.

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

# Timestamp a file via OpenTimestamps
nu-multiproof ots stamp multiproofs/tree-root.txt
# Upgrade pending attestation to Bitcoin (hours/days later)
nu-multiproof ots upgrade multiproofs/ots-timestamps/tree-root.ABCD1234/tree-root.ots
# Inspect a timestamp
nu-multiproof ots info tree-root.ots
# Independently verify the Bitcoin anchor against real block headers
nu-multiproof ots verify multiproofs/ots-timestamps/tree-root.ABCD1234/tree-root.ots

# Sign a file with your SSH key. The key must already be registered in
# multiproofs/pubkeys/ — signing resolves the principal out of the trust list,
# so an unregistered key is refused rather than signing under a name nothing
# reading the artifact could resolve. `init --pubkey` is what registers one.
nu-multiproof ssh-sign sign multiproofs/tree-root.txt --key ~/.ssh/id_ed25519
# Verify signatures against bundled public keys
nu-multiproof ssh-sign verify multiproofs/tree-root.txt
# The principal a key signs under — what `merkle verify --signer` takes
open --raw ~/.ssh/id_ed25519.pub | nu-multiproof pubkey fingerprint
# The canonical pubkey bytes the fingerprint is taken over (type + base64 + \n)
open --raw ~/.ssh/id_ed25519.pub | nu-multiproof pubkey canonical

# Derive the merkle root over the manifest and write multiproofs/tree-root.txt (seal does this automatically)
nu-multiproof merkle write-root
# Extract a compact inclusion proof for one manifest row
nu-multiproof merkle prove README.md
# Verify it: fold to the signed root, check signatures, content, OTS status
nu-multiproof merkle verify multiproofs/inclusion-proofs/README.md.multiproof.json

# The whole pipeline in one step: manifest → merkle root → SSH signature →
# OTS stamp, then upgrade any pending stamp it finds. This is the command
# everything below is written in terms of.
nu-multiproof seal
nu-multiproof seal --repo path/to/other/repo   # seal a repo other than the CWD's

# The CID v0 of any bytes, standalone — the same one tree-hashes puts in content_cid
open --raw README.md | nu-multiproof cid-v0
```

The signing key comes from the target repo's `git config user.signingKey`; `seal` has no `--key` flag, because a repo's signing identity belongs in its config rather than in each invocation. `ssh-sign sign --key` still gives explicit key choice for a one-off.

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

CIDs are computed in-process, in Nushell — no `ipfs` daemon or CLI is involved, and there is only one manifest shape to sign. Content over 256 KiB is chunked and folded into a UnixFS DAG the same way the reference client does it, so `content_cid` is the CID `ipfs add` reports for that file, and the `.` row is the CID of the whole tracked tree. Reference: `nu-multiproof/_cid-helpers.nu`; conformance vectors in `tests/test_cid-v0.nu`, recorded from the reference client — single files from empty up to one full 262144-byte chunk, a multi-chunk file, a two-level DAG (175 chunks), a directory tree, and the directory at the HAMT threshold. The chunked and directory vectors were recorded with ipfs 0.42.0; the empty-directory CID is publicly known rather than recorded. What no vector covers is a file DAG deeper than two levels — 175 full branches, about 7.9 GB. The fold there is the same code, but nothing outside this repo pins it.

One limit, and it fails loudly rather than lying: IPFS switches a directory to a HAMT shard once its entries exceed 256 KiB by kubo's estimate (name length + 34 bytes per entry — about 6200 files with 8-character names in a single directory, and fewer as the names get longer). This builds basic directories only, so `tree-hashes` refuses such a directory instead of emitting a CID no IPFS client would reproduce.

The root CID names content, it does not publish it. Nothing here talks to IPFS, so the tree is retrievable through the network only if you add it yourself. Over a directory holding exactly the tracked files, `ipfs add -r --hidden --cid-version=0 --raw-leaves=false --hash=sha2-256 --chunker=size-262144` reproduces the `.` row (`--hidden` because `ipfs add` skips dotfiles otherwise).

## Merkle inclusion proofs

`multiproofs/tree-hashes.csv` is a flat manifest: signing it whole would mean that proving one file's inclusion requires keeping the entire CSV. The merkle layer fixes that. The CSV stays the authoritative catalogue, but `seal` also derives a binary merkle tree over its rows and signs/stamps only the one-line root statement (`multiproofs/tree-root.txt`). A consumer then holds one row plus ~log2(n) sibling hashes — for a million files, ~20 hashes instead of a million rows. (Git's own trees cannot do this job: they branch wide, so a path through them lists every sibling in each directory — it grows with directory width and leaks the neighbors' filenames.)

The root also authenticates the whole catalogue, indirectly: it is computed from every row, so anyone holding the full CSV can rebuild the tree and must land on the signed root — alter one row and the roots diverge. That is why `seal` itself no longer signs the CSV: earlier versions did during a transition, and git tag `pre-drop-manifest-sig` marks the last version that produced such a signature. `ssh-sign sign multiproofs/tree-hashes.csv` still works, and a signature over the manifest is cleared by exactly the same rule as one over the root statement — it survives a reseal that regenerates identical bytes, and goes when the bytes change (pinned by "a deliberate manifest signature survives an unchanged reseal"). One deliberate boundary: the root commits to the parsed row data, not the CSV's exact bytes (column order, quoting style) — leaf serialization uses parsed field values because CSV quoting is not canonical.

A consumer's full artifact set: the proof file (`merkle prove <filepath>`), `tree-root.txt`, a `.sig` over it, the signer's pubkey from `multiproofs/pubkeys/`, and — for the time anchor — the `tree-root.*` OTS bundle.

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
| `"unverifiable"` | there is nothing to re-derive from — a directory row outside a git repo, or a leaf carrying no commitment at all |

When `multiproofs/tree-hashes.csv` is there, `merkle verify` also rebuilds the root from it and reports it as `manifest_root`; a value differing from the signed `root` blocks `valid`. The statement is a claim about that catalogue, and the two are written in separate steps — an interrupted `seal`, or a bare `tree-hashes` run afterwards, leaves a CSV no signature covers while old proofs still fold to the old statement. A portable bundle carries no CSV, so `manifest_root` is `null` there and nothing is cross-checked. (Pinned by the test "a manifest that no longer yields the signed root is caught".)

### Verifying without the origin repo

The artifact set is portable. Lay it out in a plain directory — no git, no clone of the origin repo — mirroring the `multiproofs/` layout, and point `merkle verify` at it with `--repo`:

```
bundle/
  README.md                                # the proven file, at the leaf's filepath
  multiproofs/tree-root.txt                # + its .<fingerprint>.sig alongside
  multiproofs/pubkeys/<fingerprint>.pub
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

An OTS bundle directory (`multiproofs/ots-timestamps/<stem>.<hash-prefix>/`) is self-contained provenance: every file needed to assert *"content C existed at time T, anchored to Bitcoin block B, and signer X endorsed C"* lives in the directory, with no reference to anything outside it. Read the two halves separately: the anchor covers the stamped snapshot's hash and nothing else, so it dates C, not the endorsement. A `.sig` copied in here sits *beside* the proof — a filesystem fact, not something the chain commits to — and a signature made today can be dropped into a bundle stamped a year ago. To date an endorsement, stamp the signature; see "Dating the endorsement" below.

- `<stem>.<ext>` — frozen content snapshot (the stamped file's bytes at stamp time)
- `<stem>.ots` — the timestamp over the snapshot's hash. A fresh `ots stamp` writes a *pending* calendar attestation here; `ots upgrade` replaces it in place with the Bitcoin-anchored one once a block confirms it, hours or days later. Until that upgrade runs, the bundle carries the content and the signature but not yet the anchor, so it cannot make the "at time T, in block B" half of the claim above
- `<stem>.<ext>.<fingerprint>.sig` — SSH signature over the snapshot, copied in at stamp time so it survives the next `seal` (which overwrites the live sig). Every signature sitting beside the stamped file is copied, the bare `<stem>.<ext>.sig` form included, so a bundle carries one per signer rather than one (pinned by the test "stamp snapshots every signature beside the file it stamps"). `seal` signs before it stamps, so its own bundles always carry at least its own (pinned by "seal stamps the root statement into the target repo and bundles its signature")
- `<stem>.<YYYYmmdd-HHMMSS>-<8 hex of its own sha256>.ots` — a previous proof of the same content, archived by the re-stamp that replaced it. Same content, different nonce and calendar response, so it is an independent attestation worth keeping; the hash in the name makes the archive name collision-proof for two stamps in one second (pinned by the test "rapid re-stamps each keep their own proof")
- `<stem>.<YYYYmmdd-HHMMSS>-<8 hex of its own sha256>.ots`, **written by a failed stamp** — when `<stem>.ots` cannot be written (another stamp won the race), this run's assembled proof is parked beside it rather than dropped: the nonce binding it to this file exists only in that run. The name shape is identical to the archived form above, so the two are not distinguishable on disk — both are genuine proofs of the bundle's content, which is why `merkle verify` discovers proofs by content rather than by name. The command still exits non-zero and names the path

One more form is written **outside** any bundle, directly under `multiproofs/ots-timestamps/`:

- `<stem>.<hash-prefix>.rejected-<YYYYmmdd-HHMMSS>-<8 hex of its own sha256>.ots` — a calendar answer that did not parse into a readable proof. No bundle is created, and these bytes are deliberately not a proof; they are kept because the digest already reached the calendar and the nonce is unrecoverable otherwise. The reference `ots` CLI reads constructs this parser refuses (forks, for one), so recovery may still be possible from them (pinned by the test "rejected stamps in the same second each keep their nonce")

`seal` produces this layout automatically. The next `seal` regenerates `multiproofs/tree-hashes.csv` and re-signs `tree-root.txt` when its bytes changed — previous bundles remain intact because the frozen copy and its sig were already copied in. New seals produce only `tree-root.*` bundles: the manifest is neither signed nor stamped anymore, since the root statement is derived from every manifest row, so its signature and Bitcoin anchor cover the full CSV. Archival `tree-hashes.*` bundles (including `origin-proofs/`) stay valid as-is; the transition-era ones may also carry a CSV sig.

Every bundle committed to this repo predates the fingerprint principal, so none of them matches the `.sig` grammar above — read them as history, not as examples. Their signatures carry a key-file label where a fingerprint now goes (`tree-root.txt.maxim-uvarov2.sig`), and the two `origin-proofs/` bundles carry a signature over the **`.ots`** rather than over the frozen snapshot (`tree-hashes.ots.maxim-uvarov2.sig`), added by hand after stamping. `ots stamp` writes neither shape: it copies the signatures sitting beside the file it stamps, and `ssh-sign sign` names them by fingerprint.

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
