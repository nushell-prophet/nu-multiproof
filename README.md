# nu-multiproof

Proof of concept: Composable cryptographic proofs for git repositories, written in Nushell. No external dependencies beyond `git` and `ssh-keygen` — network calls use Nushell's built-in `http`.

🚧 The code in this repo was generated via `claude code` by the latest Anthropic model available at the time, is barely tested, and is not secure.

## What you can prove

| Claim | Proof type | Mechanism |
|-------|-----------|-----------|
| **This content existed in a signed commit** | Git merkle proof | SHA-256 merkle path from signed commit to blob, self-verifiable without the original repo |
| **This content existed at a specific time** | OpenTimestamps | Hash chain anchored to a Bitcoin block header |
| **This person signed this file** | SSH file signature | SSH-keygen signature verified against bundled public keys |

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
