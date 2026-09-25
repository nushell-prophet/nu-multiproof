# nu-multiproof

Cryptographic proofs for the files of a git repository, written in Nushell.
One command, `seal`, turns the tracked tree into a signed and timestamped statement.
Any one file can then be proven part of it
by someone holding a few small files
— no clone of the repo needed.

It is the crypto layer under [nu-cybergraph](https://github.com/nushell-prophet/nu-cybergraph),
where every link is a signed claim that has to stay checkable for years.

No external dependencies beyond `git`, `ssh-keygen` and `chmod`
— network calls use Nushell's built-in `http`.

🚧 A proof of concept.
The code was generated with Claude Code
and has never been reviewed by an outside cryptographer
— do not rely on it for anything that matters.
Its guards are tested against hostile artifacts built by hand,
not only against the output of its own builder;
that shows the guards do something, not that the design is sound.

## What you can prove

- **This content existed at a specific time**
  — OpenTimestamps:
  a hash chain anchored to a Bitcoin block header.
- **This file was in the catalogued snapshot**
  — a merkle inclusion proof:
  an RFC 6962-style binary tree over the manifest rows,
  where one signed 32-byte root verifies a proof of ~log2(n) hashes.
- **This seal is no OLDER than a moment**
  — a beacon:
  a recent Bitcoin block, named in the signed statement
  — its hash could not have been known before that block was mined.

Each claim is checked on its own.
The beacon is the one that is not *produced* on its own:
it is a field of the root statement,
so it is minted when that statement is written.

Signing is the step under two of the claims, not a fourth one:
the root statement that `ssh-sign` signs carries the merkle root and the beacon.
The timestamp does not rest on a key
— an OTS proof is a hash compare —
which is why the content and its signature are stamped separately (see [Dating the endorsement](SPEC.md#dating-the-endorsement)).

A signer is named by its **key fingerprint**:
the SHA-256 of the key blob, as 64 lowercase hex.
Nothing is read from a file name or a key comment.
A fingerprint names a key, not a person,
and binding it to a person is the verifier's step
— see [Verifying commit signatures](#verifying-commit-signatures).
The details are under [Signers](SPEC.md#signers).

Any git repo works, SHA-1 or SHA-256:
the merkle tree and the CID hash file contents, not git objects.

## Prerequisites

- [Nushell](https://www.nushell.sh/)
  — the suite passes on 0.115.1;
  the minimum supported version has not been established
- `git` (any repo)
- `chmod`
  — `pubkey canonical` writes a key to a temp file at 0600 before handing it to `ssh-keygen`,
  so it sits on the same path as `ssh-keygen` below and is checked for at the same moment
- `ssh-keygen`, from OpenSSH
  — for signing, and also for **verifying**:
  `pubkey canonical` defers to `ssh-keygen` to decide what is a well-formed key,
  so anything that renders a trust list needs it.
  That includes `init`, `ssh-sign verify` and `merkle verify`.
  A missing binary is reported as a broken toolchain, never as a verdict about the artifact

## Quick start

Inside the repo you want to seal,
with `use` pointing at the `nu-multiproof/` module directory of this checkout:

```nushell no-run
use path/to/this/checkout/nu-multiproof/

git config user.signingKey ~/.ssh/id_ed25519.pub   # seal signs with the repo's git signing key
nu-multiproof init                                 # create multiproofs/ and register that key
nu-multiproof seal                                 # manifest → merkle root → signature → timestamp
nu-multiproof merkle prove README.md               # a compact proof for one file
nu-multiproof merkle verify multiproofs/inclusion-proofs/README.md.multiproof.json
```

`seal` posts a digest to the public OpenTimestamps calendar, a permanent public write;
`seal --no-stamp` seals offline.
The timestamp stays *pending* until Bitcoin confirms it, hours or days later;
the next `seal`, or `ots upgrade`, completes it.

## All commands

Every command that works on a repo takes `--repo`,
defaulting to the git root of the current directory
— `init`, `tree-hashes`, `tree-hashes root-cid`, `merkle write-root`, `merkle prove`, `merkle verify`, `seal` and `seal status`.
`ssh-sign sign`, `ssh-sign verify` and `ots stamp` predate the rule:
they resolve the git root of the current directory with no way to override it,
so a chain using them runs from inside the target repo.
The remaining commands take bytes or a file path and no repo at all.

```nushell no-run
use nu-multiproof/   # from this repo's root; from elsewhere, give the path

# The whole pipeline in one step; its five stages are listed below.
nu-multiproof seal
nu-multiproof seal --repo path/to/other/repo   # seal a repo other than the CWD's
nu-multiproof seal --propose-commit            # leave the git commit in the prompt, unrun
nu-multiproof seal --no-stamp                  # offline: no beacon, no timestamp
nu-multiproof seal --no-content-anchor         # anchor the signatures only — see SPEC.md
nu-multiproof seal status                      # every bundle and its anchor state; not a verdict

# The steps seal wraps, one by one
nu-multiproof init                             # create multiproofs/, register the signing key
nu-multiproof tree-hashes                      # the content manifest (SHA-256, git hashes, IPFS CID v0)
nu-multiproof merkle write-root                # the root statement, multiproofs/tree-root.txt
nu-multiproof ssh-sign sign multiproofs/tree-root.txt --key ~/.ssh/id_ed25519   # the key must be registered
nu-multiproof ots stamp multiproofs/tree-root.txt   # after signing: it copies in the signatures beside the file

# Proofs
nu-multiproof merkle prove README.md           # an inclusion proof for one manifest row
nu-multiproof merkle verify multiproofs/inclusion-proofs/README.md.multiproof.json
nu-multiproof ssh-sign verify multiproofs/tree-root.txt   # every signature, against the registered keys

# Timestamps and the lower bound
nu-multiproof ots upgrade multiproofs/ots-timestamps/tree-root.ABCD1234/tree-root.ots   # pending → Bitcoin
nu-multiproof ots info multiproofs/ots-timestamps/tree-root.ABCD1234/tree-root.ots
nu-multiproof ots verify multiproofs/ots-timestamps/tree-root.ABCD1234/tree-root.ots    # against real block headers
nu-multiproof beacon latest                    # the cross-checked block seal writes into the statement
nu-multiproof beacon verify multiproofs/tree-root.txt

# Keys and bytes
open --raw ~/.ssh/id_ed25519.pub | nu-multiproof pubkey fingerprint   # the principal a key signs under
open --raw ~/.ssh/id_ed25519.pub | nu-multiproof pubkey canonical     # the bytes that fingerprint is taken over
open --raw README.md | nu-multiproof cid-v0    # the CID v0 of any bytes, as tree-hashes computes it
```

### The five stages of `seal`

This document and `SPEC.md` refer to these by number.

1. **Upgrade** every pending `.ots` it finds — opportunistic, so earlier seals progress.
   Still pending is silent; any other failure is printed and skipped.
2. **Beacon** — mint the lower time bound and carry it into the statement stage 3 writes.
   It runs before anything on disk is touched, so an explorer outage costs nothing.
3. **Manifest and root** — regenerate `multiproofs/tree-hashes.csv` from the worktree,
   then derive `multiproofs/tree-root.txt` from it.
4. **Sign** the root statement.
5. **Stamp** the root statement and every signature over it, into one bundle.

`--no-stamp` skips stages 2 and 5; `--no-content-anchor` runs stage 5 over the signatures only.
Stage 1 is not skipped by either,
so `--no-stamp` reaches the network anyway when the tree holds a pending `.ots`
— it seals offline only in a repo with nothing left to upgrade.

`seal` refuses a repo with no tracked files:
the root of a no-file tree is the same for every empty repo,
so a signature over it would state nothing about this one.
A repo that has files but no commit yet seals normally
— only `multiproofs/snapshot.txt` is withheld, since there is no HEAD to name.
The same holds for a dirty tree, and a stale snapshot record is deleted rather than left behind.

`init` is safe to re-run.
It creates nothing that is already there,
names the key already registered,
and exits 0.
A re-run with `--pubkey` adds that key if the trust list does not hold it,
and says so if it does;
a bare re-run registers the signing key from `git config`, which after the first run is already there.

### Sealing under an explicit key

The signing key comes from the target repo's `git config user.signingKey`;
`seal` has no `--key` flag,
because a repo's signing identity belongs in its config rather than in each invocation.
To seal under a different key, run the steps `seal` wraps:

```nushell no-run
nu-multiproof init --pubkey ./otherkey.pub          # register it: sign refuses an unregistered key
nu-multiproof tree-hashes                           # regenerate the manifest
nu-multiproof merkle write-root                     # mint the root statement over it
nu-multiproof ssh-sign sign multiproofs/tree-root.txt --key ./otherkey
nu-multiproof ots stamp multiproofs/tree-root.txt   # optional — the time anchor
```

`merkle write-root` mints no beacon of its own:
its `--beacon` defaults to `none`, so this chain produces a statement with no lower bound
unless a token from `beacon latest` is passed in.

That is what `merkle write-root` is for on its own:
it is the only way to mint `tree-root.txt` without `seal`,
and therefore without `seal`'s key.
What follows it is a plain `ssh-sign sign`,
so a second signer is added the same way
— sign the existing `tree-root.txt`, no re-rooting.

Two things this path does not buy.
Staying offline is one:
`seal --no-stamp` already skips the calendar post,
so reach for the manual chain only for the key.
The other is a repo elsewhere
— `ssh-sign sign` takes `--pubkeys-dir` but no `--repo`,
so run the chain from inside the target repo.

Its cost is state between steps:
a manifest regenerated after the root was signed leaves a CSV no signature covers.
`merkle verify` catches exactly that and reports it as `manifest_root`
— see [Merkle inclusion proofs](SPEC.md#merkle-inclusion-proofs).

### Committing a seal

`seal` does not commit,
and `--propose-commit` does not change that.
It writes the commit into your prompt with `commandline edit` and stops there,
so nothing runs until you read it, edit it and press enter.
What it removes is the other failure:
a seal landing under "wip", or spread over three commits,
which makes the log useless for the one question it should answer
— when was this root sealed.

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

A block with variables rather than one long line,
because the message is meant to be edited before it runs
and a body escaped into `\n` inside a quoted argument is the one shape that cannot be edited comfortably.
`$msg` gives the body real lines;
`$repo` is used twice.
Splitting `add` from `commit` costs nothing:
Nushell throws on a non-zero external exit,
so a failed `add` still stops before `commit`.

Why the block is shaped this way, and what it does not sanitize, is under [Committing a seal](SPEC.md#committing-a-seal).

## Exit status

A verdict is a returned value, not an exit code.
`ots verify`, `beacon verify`, `merkle verify` and `ssh-sign verify` all return a record carrying `valid`,
and all four **exit 0 whether that field is `true` or `false`**.
So a CI job that only reads the exit code passes on a tampered artifact.

Pass `--fail` to those four commands to make a not-valid result exit 1.
Without it the record is returned and the caller decides,
so `--fail` is the flag that turns a report into a gate.

Two of the four are pinned by tests
— "verify --fail errors on invalid signature" for `ssh-sign verify`,
and the `merkle verify` cases in `tests/test_merkle.nu`.
`ots verify --fail` and `beacon verify --fail` behave the same way but no test holds them there.

Everything else exits non-zero by throwing, with no flag needed.
That is the difference between a verdict and a broken run,
and the two never share an exit code:

- A refusal to make a claim at all
  — `merkle verify --signer <fingerprint>` where the trust list holds no such key,
  `merkle prove <path>` where the path is not in the manifest,
  `ots verify` on a proof that is still pending.
- A toolchain problem
  — `ssh-keygen` or `chmod` missing from `PATH`.
- An outage
  — fewer than `--min-sources` explorers answering, or explorers disagreeing.
- `ots stamp` losing the race for `<stem>.ots`.
  The digest already reached the calendar, so the assembled proof is parked beside it
  and the path is named in the error.
- `seal --no-stamp` together with `--no-content-anchor`, refused before anything is touched.

`nu toolkit.nu test` exits non-zero on any failing test.
That is `--fail` again, on by default there, with `--no-fail` to opt out.

## Verifying without the origin repo

The artifact set is portable.
Lay it out in a plain directory
— no git, no clone of the origin repo —
mirroring the `multiproofs/` layout,
and point `merkle verify` at it with `--repo`:

```text
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

The proof file belongs under `multiproofs/`, not at the bundle root.
Everything under that prefix is excluded from the manifest and from the re-derivation,
so a proof of the `.` row does not fold its own proof file into the CID it is checking.
At the root it would,
and the bundle would report itself as tampered.

This is a supported contract, pinned by a test
— not an accident of path handling:
an explicit `--repo` is taken as-is (no git required),
and every lookup is layout-relative to it.
One caveat:
`seal`'s opportunistic OTS upgrade only walks the target repo's own `multiproofs/ots-timestamps/`,
so a bundle's `pending` stamp stays pending until you run `ots upgrade` on it yourself.

A proof of a **directory row** (or of `.`) works the same way, with one extra thing in the bundle:
the subtree itself, laid out under the row's `filepath`.
A directory's `content_cid` commits to every entry under it,
so it can only be re-derived from the files,
and a compact proof cannot stand in for them.
Away from the origin repo there is no git index to enumerate from,
so `merkle verify` walks the bundle instead
— dropping `multiproofs/` and `.git`, the two directories the manifest never covered and which sit *inside* the walked tree when the row is `.`.
Dropping `.git` is what lets a bundle be a clone of the sealed repo,
the most ordinary way one travels (pinned by "the root row of a bundle distributed as a git repo still verifies").

That walk trusts the bundle for the file list,
and does not need to:
the sealed `content_cid` is what checks the list.
Under the proven row, a bundle that drops a file, adds one, or alters a byte folds to a different CID and is refused
— pinned by "a non-git bundle carrying the sealed subtree verifies a directory row" (the same fixture verifying), "a bundle that drops a file from a proven directory is refused", "a bundle that adds a file under a proven directory is refused", and "a non-git bundle carrying the wrong bytes under a proven directory is refused".
Files *outside* the proven row's subtree are not covered and never were:
the walk is scoped to that subtree,
so an unrelated file
— or a stray symlink —
beside it does not turn a genuine proof into a report of tampering.
What git answers in a live worktree is a different question again,
which files are untracked build output the seal never covered.

**Pass `--bundle` for an artifact someone sent you.**
Without it, `merkle verify` takes the git arm whenever the target *is* a git repo root
— and a sender can make that true.
A `.git` costs nothing to ship,
and one whose index lists exactly the sealed paths hands the sender the file set:
the same bundle carrying an extra file under the proven directory answers `valid: true` with that `.git` present and `valid: false` without it.
`--bundle` ignores any index the target carries and always walks,
so the enumeration is the verifier's choice rather than the artifact's (pinned by "a bundle cannot hand itself the git arm by shipping its own index").
Distributing a bundle as a git repo is ordinary,
so this is not an exotic shape.
The flag is a no-op for file rows, which never consult git.

Which arm ran is reported as `content_enumeration`
— `"git-index"` or `"walk"`, and `null` for a row that consulted no file set.
The two readings of `content_verified: true` are different claims ("the tracked files are the sealed ones" versus "everything the sender shipped folds to the sealed CID"),
so a consumer keying on `.valid` needs to see which one it got.
The flag lets a verifier choose the arm;
the field lets it check what it chose.

`content_verified: "unverifiable"` is therefore left for one case only:
a row that commits to no content at all
— no `content_sha256` and no `content_cid`.
It still blocks `valid`,
because a row whose only commitment cannot be checked must not read as one that was.

## Origin proofs

This repository contains proofs of how it came to exist in [`multiproofs/origin-proofs/`](multiproofs/origin-proofs/).
See that directory's README for the full story;
in brief:

- **`tree-hashes.CCA016A8/`**
  — Bitcoin block 939896 timestamp of the extracted subtree (source repo snapshot), with SSH signature
- **`tree-hashes.93223B2F/`**
  — bridge stamp:
  first OTS made from inside this repo post-extraction, Bitcoin block 940583

These are archival artifacts.
Ongoing operational timestamps live in [`multiproofs/ots-timestamps/`](multiproofs/ots-timestamps/),
whose layout `SPEC.md` specifies under [Timestamp bundles](SPEC.md#timestamp-bundles).

## Verifying commit signatures

Signing here is occasional rather than policy:
agent-made commits carry no signature,
and the hand-signed ones are scattered through the log,
so `git log --show-signature` prints nothing for most of it.
The commit "revoke claude-code signing key" is one signed commit to try the recipe on
— found by its subject, since a sha changes whenever history is rewritten.
The recipe stays here because `multiproofs/pubkeys/` is exactly what an `allowed_signers` file is rendered from.

Verifying an SSH-signed commit involves two distinct checks:

1. **Cryptographic validity**
   — does the signature mathematically match the commit bytes under some public key?
   Key-agnostic, no trust required.
2. **Trust**
   — is that public key one *you* choose to recognize as a valid signer?
   Verifier-side policy.

Git conflates them:
it refuses to verify SSH signatures unless `gpg.ssh.allowedSignersFile` is configured and points to an existing file.
That file maps principals → keys → namespaces;
it is your **local trust list**, not part of any commit.
Setting it is a statement *you* make about which keys you trust
— the repo cannot make it for you.

`multiproofs/pubkeys/` is this project's source of truth for who can sign.
Nothing here writes the trust file for you:
that file *is* your statement about which keys you accept,
so building it is your step, not the repo's.
The format is one line per key
— `<principals> namespaces="git" <keytype> <base64>`.
The `*` principal below is collective trust:
the key is in this project's list, with no personal identity attached to it.

### One-shot inspection

`git -c key=value` overrides config for a single invocation, no persisted state:

```nushell no-run
let signers = "/tmp/nu-multiproof-signers"
ls --all multiproofs/pubkeys | get name | where ($it | path parse | get extension) == "pub" | each {|f| $"* namespaces=\"git\" (open --raw $f | split row --regex '\s+' | first 2 | str join ' ')" } | str join "\n" | save --force $signers
git -c $"gpg.ssh.allowedSignersFile=($signers)" log --format='%h %G? %an %s'   # G = good, N = unsigned
git -c $"gpg.ssh.allowedSignersFile=($signers)" log --show-signature -1 --grep "revoke claude-code signing key"
```

The first command is where to start:
`%G?` marks every commit `G` or `N`,
so it shows both that the trust list resolves and which commits it has anything to say about.
`--show-signature -1` on an unsigned commit prints no signature line at all.

`first 2` keeps the key type and the base64 blob and drops the trailing comment (`alice@laptop`)
— it is not part of the trust statement and differs per machine.

### Per-clone setup

For repeated inspection, write the same file inside this clone's `.git/` and point its **local** git config at it:

```nushell no-run
let signers = $"(git rev-parse --git-dir | str trim)/allowed_signers"
ls --all multiproofs/pubkeys | get name | where ($it | path parse | get extension) == "pub" | each {|f| $"* namespaces=\"git\" (open --raw $f | split row --regex '\s+' | first 2 | str join ' ')" } | str join "\n" | save --force $signers
git config gpg.ssh.allowedSignersFile $signers
```

`.git/config` lives inside this clone's `.git/` directory
— it is not tracked, not pushed, not shared with collaborators.
Plain `git log --show-signature` now resolves cleanly.
Re-run the render after any change to `multiproofs/pubkeys/`.

### Reading the output

```text
Good "git" signature for * with ECDSA-SK key SHA256:7SOGNZ2C…
```

- `Good`
  — both checks above passed.
- `for *`
  — the matched principal is the `*` you wrote into the file:
  confirms the key is in the project's trust list, but does not attach a personal identity.
  This is the appropriate trust statement for a project's tracked signers
  — collective trust, not individual identification.

One caveat about where the keys come from:
`multiproofs/pubkeys/` travels inside the repo under examination,
so rendering the trust file from it and then verifying that repo's commits proves the repo agrees with itself.
Anyone can fork, add their own key and re-sign.
To make it an identity check, compare the fingerprint git reports against one you hold from elsewhere
— the same verifier-side step `merkle verify --pubkeys-dir` exists for.

## Limitations

Collected here because each is easy to miss in the section that explains it.

**The work behind a Bitcoin header is not checked.**
`ots verify` recomputes the header's hash and its merkle binding,
but `bits` is read out of the very header under examination,
so "the hash meets its own target" proves nothing.
Independent explorers agreeing on the height to hash mapping is the whole defence
— see [Verifying a timestamp](SPEC.md#verifying-a-timestamp).

**A trust list travelling inside the artifact proves only self-consistency.**
A default `valid: true` says the bundle agrees with itself.
Anyone can fork, `init` with their own key and re-`seal`.
`--pubkeys-dir` and `--signer` are how a verifier states its own policy.

**Three commands take no `--repo`** — `ssh-sign sign`, `ssh-sign verify` and `ots stamp`.
They resolve the git root of the current directory and offer no override.

**`seal`'s opportunistic upgrade walks only the target repo's bundles.**
A bundle someone sent you keeps its `pending` stamp until `ots upgrade` is run on it directly.

**No test vector covers a file DAG deeper than two levels** — about 7.9 GB.
The fold there is the same code, but nothing outside this repo pins it.

**A directory that would become a HAMT shard is refused, not approximated.**
Roughly 6200 files with 8-character names in one directory, fewer as names grow.
`tree-hashes` errors rather than emit a CID no IPFS client would reproduce.

**The commit proposal is not sanitized for display.**
A repo path holding ANSI escapes reaches the prompt raw and can repaint the line before you press enter.
The guarantee is that the block parses as one command, never that it renders honestly.

**Two of the four `--fail` paths have no test** — `ots verify` and `beacon verify`.
Both behave like the two that do, checked by running, but nothing holds them there.

**Eleven of the fifteen bundles committed here carry no endorsement anchor and cannot get one**,
and the two under `origin-proofs/` carry a signature over the `.ots` rather than over the snapshot
— a shape `ots stamp` never writes.
They are history, not examples of the grammar.

## Testing

Tests use [nutest](https://github.com/vyadh/nutest), cloned as a sibling directory.
Run them from the repo root:

```nushell no-run
git clone https://github.com/vyadh/nutest ../nutest
nu toolkit.nu test              # runs tests/; exits non-zero on any failure
nu toolkit.nu test --network    # runs tests-network/ instead — reaches the internet, and
                                # one test writes a permanent public timestamp
```

The suite runs on one thread by default;
`CLAUDE.md` explains why, and what `--threads 0` risks.

## License

MIT
