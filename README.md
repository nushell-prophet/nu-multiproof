# nu-multiproof

Composable cryptographic proofs for git repositories, written in Nushell. No external dependencies beyond `git`, `ssh-keygen`, and `curl`.

## What you can prove

| Claim | Proof type | Mechanism |
|-------|-----------|-----------|
| **This content existed in a signed commit** | Git merkle proof | SHA-256 merkle path from signed commit to blob, self-verifiable without the original repo |
| **This content existed at a specific time** | OpenTimestamps | Hash chain anchored to a Bitcoin block header |
| **This person signed this file** | SSH file signature | SSH-keygen signature verified against bundled public keys |

Each proof type is independent. Use one, two, or all three.

## Quick start

```nushell
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
nu-multiproof git-proof render-allowed-signers --to allowed_signers

# Timestamp a file via OpenTimestamps
nu-multiproof ots stamp multiproofs/tree-hashes.csv
# Upgrade pending attestation to Bitcoin (hours/days later)
nu-multiproof ots upgrade multiproofs/ots-timestamps/tree-hashes.ABCD1234/tree-hashes.ots
# Promote an upgraded provenance bundle into ots-verified/ (move + optional sign + rename to tree-hashes)
nu-multiproof ots promote multiproofs/provenance/ots-pending/<bundle>/<bundle>.ots --key ~/.ssh/id_ed25519
# Inspect a timestamp
nu-multiproof ots info tree-hashes.ots

# Sign a file with your SSH key
nu-multiproof ssh-sign sign tree-hashes.csv --key ~/.ssh/id_ed25519
# Verify signatures against bundled public keys
nu-multiproof ssh-sign verify tree-hashes.csv
```

## Prerequisites

- [Nushell](https://www.nushell.sh/) 0.101+
- `git` (SHA-256 repos supported)
- `ssh-keygen` (for SSH signing)
- `curl` (for OpenTimestamps calendar servers)

### Testing

Tests use [nutest](https://github.com/vyadh/nutest). Clone it as a sibling directory:

```bash
git clone https://github.com/vyadh/nutest ../nutest
```

```nushell
use toolkit.nu *; main test
```

## Provenance

This repository contains proofs of its own origin in `multiproofs/provenance/`:

- **`git-proof/`** — merkle proof that commit [`ff8545e`] in the source repository was signed with an ECDSA-SK hardware key and contained the exact files in `nu-multiproof/`
- **`ots-verified/tree-hashes.CCA016A8/`** — Bitcoin block 939896 timestamp of an earlier content snapshot, with SSH signature
- **`ots-pending/`** — timestamp of the current content, awaiting Bitcoin confirmation

After `ots upgrade` confirms a pending bundle (hours-to-days after stamping), run `ots promote` to optionally sign the `.ots`, move the bundle into `ots-verified/`, and rename filenames to match the verified-bundle convention. Then commit the rename and update the block-height reference in this section.

Verify the git proof:

```nushell
use nu-multiproof/
nu-multiproof git-proof verify multiproofs/provenance/git-proof
```

## Verifying commit signatures

Commits in this repo are SSH-signed. Verifying an SSH-signed commit involves two distinct checks:

1. **Cryptographic validity** — does the signature mathematically match the commit bytes under some public key? Key-agnostic, no trust required.
2. **Trust** — is that public key one *you* choose to recognize as a valid signer? Verifier-side policy.

Git conflates them: it refuses to verify SSH signatures unless `gpg.ssh.allowedSignersFile` is configured and points to an existing file. That file maps principals → keys → namespaces; it is your **local trust list**, not part of any commit. Setting it is a statement *you* make about which keys you trust — the repo cannot make it for you.

`multiproofs/pubkeys/` is this project's source of truth for who can sign. `git-proof render-allowed-signers --to <path>` writes those keys into a correctly-formatted trust file. It does **not** mutate git config — wiring is the caller's choice.

### One-shot inspection

`git -c key=value` overrides config for a single invocation, no persisted state:

```nushell
use nu-multiproof/
nu-multiproof git-proof render-allowed-signers --to /tmp/nu-multiproof-signers
git -c gpg.ssh.allowedSignersFile=/tmp/nu-multiproof-signers log --show-signature -1
```

### Per-clone setup

For repeated inspection, render once and point this clone's **local** git config at the file:

```nushell
let signers = $"(git rev-parse --git-dir | str trim)/allowed_signers"
nu-multiproof git-proof render-allowed-signers --to $signers
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
