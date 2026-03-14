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

# Timestamp a file via OpenTimestamps
nu-multiproof ots stamp multiproofs/tree-hashes.csv
# Upgrade pending attestation to Bitcoin (hours/days later)
nu-multiproof ots upgrade multiproofs/ots-timestamps/tree-hashes.ABCD1234/tree-hashes.ots
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

Verify the git proof:

```nushell
use nu-multiproof/
nu-multiproof git-proof verify multiproofs/provenance/git-proof
```

## License

MIT
