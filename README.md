# nu-multiproof

Proof of concept: Composable cryptographic proofs for git repositories, written in Nushell. No external dependencies beyond `git` and `ssh-keygen` — network calls use Nushell's built-in `http`.

🚧 The code in this repo was generated via `claude code` by the latest Anthropic model available at the time, is barely tested, and is not secure.

## What you can prove

| Claim | Proof type | Mechanism |
|-------|-----------|-----------|
| **This content existed in a signed commit** | Git merkle proof | SHA-256 merkle path from signed commit to blob, self-verifiable without the original repo |
| **This content existed at a specific time** | OpenTimestamps | Hash chain anchored to a Bitcoin block header |
| **This person signed this file** | SSH file signature | SSH-keygen signature verified against bundled public keys |
| **This file was in the catalogued snapshot** | Merkle inclusion proof | RFC 6962-style binary tree over the manifest rows; one signed 32-byte root verifies a proof of ~log2(n) hashes |

Each proof type is independent. Use one, two, or all three.

## Quick start

```nushell no-run
use nu-multiproof/

# Bootstrap multiproofs/ directory in your repo
nu-multiproof init

# Generate content manifest (SHA-256, git hash, IPFS CID v0)
nu-multiproof tree-hashes

# Extract a git merkle proof for specific files
nu-multiproof git-proof extract src/main.nu README.md
# Verify it (works without the original repo)
nu-multiproof git-proof verify proof/
# Render multiproofs/pubkeys/ into an allowed_signers file for `git verify-commit`
nu-multiproof git-proof render-allowed-signers allowed_signers

# Timestamp a file via OpenTimestamps
nu-multiproof ots stamp multiproofs/tree-hashes.csv
# Upgrade pending attestation to Bitcoin (hours/days later)
nu-multiproof ots upgrade multiproofs/ots-timestamps/tree-hashes.ABCD1234/tree-hashes.ots
# Inspect a timestamp
nu-multiproof ots info tree-hashes.ots
# Independently verify the Bitcoin anchor against real block headers
nu-multiproof ots verify multiproofs/ots-timestamps/tree-hashes.ABCD1234/tree-hashes.ots

# Sign a file with your SSH key
nu-multiproof ssh-sign sign tree-hashes.csv --key ~/.ssh/id_ed25519
# Verify signatures against bundled public keys
nu-multiproof ssh-sign verify tree-hashes.csv

# Derive the merkle root over the manifest (seal does this automatically)
nu-multiproof merkle root
# Extract a compact inclusion proof for one manifest row
nu-multiproof merkle prove README.md
# Verify it: fold to the signed root, check signatures, content, OTS status
nu-multiproof merkle verify multiproofs/inclusion-proofs/README.md.multiproof.nuon
```

## Prerequisites

- [Nushell](https://www.nushell.sh/) 0.101+
- `git` (SHA-256 repos supported)
- `ssh-keygen` (for SSH signing)

### Testing

Tests use [nutest](https://github.com/vyadh/nutest). Clone it as a sibling directory:

```bash
git clone https://github.com/vyadh/nutest ../nutest
```

```nushell no-run
use toolkit.nu *; main test
```

## Merkle inclusion proofs

`multiproofs/tree-hashes.csv` is a flat signed manifest: proving one file's inclusion with its signature means keeping the entire CSV. The merkle layer fixes that. The CSV stays the authoritative catalogue, but `seal` also derives a binary merkle tree over its rows and signs/stamps only the one-line root statement (`multiproofs/tree-root.txt`). A consumer then holds one row plus ~log2(n) sibling hashes — for a million files, ~20 hashes instead of a million rows. (The existing git merkle proofs don't cover this: git trees branch wide, so each proof level lists every sibling in the directory — it grows with directory width and leaks the neighbors' filenames.)

The root also authenticates the whole catalogue, indirectly: it is computed from every row, so anyone holding the full CSV can rebuild the tree and must land on the signed root — alter one row and the roots diverge. That is why the separate whole-CSV signature becomes redundant and can be dropped once the transition ends. One deliberate boundary: the root commits to the parsed row data, not the CSV's exact bytes (column order, quoting style) — leaf serialization uses parsed field values because CSV quoting is not canonical.

A consumer's full artifact set: the proof file (`merkle prove <filepath>`), `tree-root.txt`, a `.sig` over it, the signer's pubkey from `multiproofs/pubkeys/`, and — for the time anchor — the `tree-root.*` OTS bundle.

`merkle verify` folds the proof to the signed root, checks the SSH signatures over the root statement, re-hashes the on-disk file against the proven `content_sha256` when present, and reports the OTS anchor as a status (`absent`/`pending`/`anchored` — a fresh seal stays pending until Bitcoin confirms, hours or days). A proof whose embedded root differs from the signed root is for a different seal and fails loudly rather than reporting invalid.

### Tree specification

Pinned exactly, so an independent implementation reproduces the root from the same CSV (reference: `nu-multiproof/_merkle-helpers.nu`, test vectors: `tests/test_merkle.nu`).

- **Leaves**: all CSV rows (directory rows and the `.` root-CID row included), sorted by `filepath` — byte-wise lexicographic over the UTF-8 path bytes, no locale, no Unicode normalization. Duplicate filepaths are a hard error.
- **Leaf bytes**: the four parsed field values (RFC 4180 CSV parsing, not raw lines) joined with `\n`: `filepath \n content_sha256 \n content_git \n content_cid`.
- **Charset constraints** (make the `\n`-join injective; reject, never normalize): `filepath` contains no bytes < 0x20; `content_sha256` is empty or 64 lowercase hex; `content_git` is empty or 40/64 lowercase hex (SHA-1 or SHA-256 git repos); `content_cid` is empty or a base58btc CIDv0 (`Qm` + 44 chars).
- **Hashing** (RFC 6962 domain separation): leaf hash = `sha256(0x00 ++ leaf_bytes)`; inner node = `sha256(0x01 ++ left ++ right)` over the raw 32-byte child hashes.
- **Shape** (RFC 6962 MTH): split the leaf list at the largest power of two below n, recurse on both halves. No padding, no last-leaf duplication. n=1: root = the leaf hash. n=0: root = `sha256("")` = `e3b0c442…`.
- **Proof steps**: `side` names the **sibling**'s position, leaf-to-root order: `side: right` → `acc = sha256(0x01 ++ acc ++ sibling)`; `side: left` → the sibling goes first.
- **Root statement**: exactly `multiproof-merkle-v1 <64 lowercase hex>` + one trailing `\n`. The statement form (not a bare hash) keeps the signature from being replayed in another hash-signing context.

## Origin proofs

This repository contains proofs of how it came to exist in [`multiproofs/origin-proofs/`](multiproofs/origin-proofs/). See that directory's README for the full story; in brief:

- **`git-proof/`** — merkle proof that commit [`ff8545e`] in the source repository was signed with an ECDSA-SK hardware key and contained the exact files in `nu-multiproof/`
- **`tree-hashes.CCA016A8/`** — Bitcoin block 939896 timestamp of the extracted subtree (source repo snapshot), with SSH signature
- **`tree-hashes.93223B2F/`** — bridge stamp: first OTS made from inside this repo post-extraction, Bitcoin block 940583

These are archival artifacts. Ongoing operational timestamps live in [`multiproofs/ots-timestamps/`](multiproofs/ots-timestamps/).

### Bundle contract

An OTS bundle directory (`multiproofs/ots-timestamps/<stem>.<hash-prefix>/`) is self-contained provenance: every file needed to assert *"signer X endorsed content C at time T, anchored to Bitcoin block B"* lives in the directory, with no reference to anything outside it.

- `<stem>.<ext>` — frozen content snapshot (the manifest at stamp time)
- `<stem>.ots` — Bitcoin-anchored timestamp over the snapshot's hash
- `<stem>.<ext>.<signer>.sig` (when signing is on) — SSH signature over the snapshot, copied in at stamp time so it survives the next `seal` (which overwrites the live sig)

`seal` produces this layout automatically. The next `seal` regenerates `multiproofs/tree-hashes.csv` and its live sig — the previous bundle remains intact because the sig was already copied in.

Verify the git proof:

```nushell no-run
use nu-multiproof/
nu-multiproof git-proof verify multiproofs/origin-proofs/git-proof
```

## Verifying a timestamp

`ots info` and `ots upgrade` only echo the block height the calendar server reported — nothing checks it against Bitcoin. `ots verify` does. It does not trust the calendar at all:

1. **Looks the block height up on independent explorers** (`mempool.space` and `blockstream.info` by default) and requires them to agree on the block hash. This is the one thing it trusts a third party for: the height → hash mapping.
2. **Fetches the raw 80-byte block header** and recomputes everything locally — the double-SHA256 block hash, the merkle-root binding (the header must commit to the exact value the proof's operations replay to), and the proof-of-work (the block hash must meet the target in the header's `bits` field). A forged or low-work header fails these checks even if an explorer served it.

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

`multiproofs/pubkeys/` is this project's source of truth for who can sign. `git-proof render-allowed-signers <path>` writes those keys into a correctly-formatted trust file. It does **not** mutate git config — wiring is the caller's choice.

### One-shot inspection

`git -c key=value` overrides config for a single invocation, no persisted state:

```nushell no-run
use nu-multiproof/
nu-multiproof git-proof render-allowed-signers /tmp/nu-multiproof-signers
git -c gpg.ssh.allowedSignersFile=/tmp/nu-multiproof-signers log --show-signature -1
```

### Per-clone setup

For repeated inspection, render once and point this clone's **local** git config at the file:

```nushell no-run
let signers = $"(git rev-parse --git-dir | str trim)/allowed_signers"
nu-multiproof git-proof render-allowed-signers $signers
git config gpg.ssh.allowedSignersFile $signers
```

`.git/config` lives inside this clone's `.git/` directory — it is not tracked, not pushed, not shared with collaborators. Plain `git log --show-signature` now resolves cleanly. Re-run the render after any change to `multiproofs/pubkeys/`.

### Reading the output

```
Good "git" signature for * with ECDSA-SK key SHA256:7SOGNZ2C…
```

- `Good` — both checks above passed.
- `for *` — the matched principal is the wildcard from the rendered file: confirms the key is in the project's trust list, but does not attach a personal identity. This is the appropriate trust statement for a project's tracked signers — collective trust, not individual identification.

### Self-verifying proof bundles

`git-proof verify <proof-bundle>` is the preferred verifier for historical commits packaged as proof bundles: it bundles its own pubkeys with the proof and verifies in a temp repo via `git -c`, with no `allowedSignersFile` setup needed and no dependence on the verifier's local trust at all.

## License

MIT
