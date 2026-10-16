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
Claude Code generated the code,
and no outside cryptographer has ever reviewed it
— do not rely on it for anything that matters.
Its guards are tested against hostile artifacts built by hand,
not only against the output of its own builder.
These tests show the guards do something.
They do not show that the design is sound.

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
The timestamp does not depend on a key
— an OTS proof is a hash compare.
For this reason, the content and its signature are stamped separately (see [Dating the endorsement](SPEC.md#dating-the-endorsement)).

The name of a signer is its **key fingerprint**:
the SHA-256 of the key blob, as 64 lowercase hex.
The tool reads nothing from a file name or a key comment.
A fingerprint names a key, not a person.
The verifier does the step that binds it to a person
— see [Verifying commit signatures](#verifying-commit-signatures).
The details are under [Signers](SPEC.md#signers).

Any git repo works, SHA-1 or SHA-256:
the merkle tree and the CID hash the contents of files, not git objects.

## Prerequisites

- [Nushell](https://www.nushell.sh/)
  — the test suite passes on 0.115.1;
  the minimum supported version is not known
- `git` (any repo)
- `chmod`
  — `pubkey canonical` writes a key to a temp file at 0600 before handing it to `ssh-keygen`,
  so it sits on the same path as `ssh-keygen` below and is checked for at the same moment
- `ssh-keygen`, from OpenSSH
  — to sign, and also to **verify**:
  `pubkey canonical` lets `ssh-keygen` decide what a well-formed key is,
  so every command that renders a trust list needs it.
  These commands include `init`, `ssh-sign verify` and `merkle verify`.
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

`seal` posts a digest to the public OpenTimestamps calendar.
This is a permanent public write.
`seal --no-stamp` seals offline.
The timestamp stays *pending* until Bitcoin confirms it, after hours or days;
the next `seal`, or `ots upgrade`, completes it.

## All commands

Every command that works on a repo takes `--repo`.
The default is the nearest directory that holds `multiproofs/`,
from the current directory up to the git root.
With none, the default is the git root.
`init` always takes the current directory,
and refuses to run inside a `multiproofs/` directory.
These commands are `init`, `tree-hashes`, `tree-hashes root-cid`, `merkle write-root`, `merkle prove`, `merkle verify`, `seal` and `seal status`.
`ssh-sign sign`, `ssh-sign verify` and `ots stamp` are older than this rule:
they resolve the same default,
and no flag overrides it.
So a chain that uses them runs from inside the target repo.
The other commands take bytes or a file path, and no repo at all.

```nushell no-run
use nu-multiproof/   # from this repo's root; from elsewhere, give the path

# The whole pipeline in one step; its five stages are listed below.
nu-multiproof seal
nu-multiproof seal --repo path/to/other/repo   # seal a repo other than the CWD's
nu-multiproof seal --propose-commit            # leave the git commit in the prompt, unrun
nu-multiproof seal --no-stamp                  # offline: no beacon, no timestamp
nu-multiproof seal --no-content-anchor         # anchor the signatures only — see SPEC.md
nu-multiproof seal --external-signer           # stage 4 on another device: run, sign the statement there, run again
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

1. **Upgrade** every pending `.ots` that it finds.
   This step is opportunistic, so earlier seals move forward.
   If a stamp is still pending, the step says nothing;
   it prints and skips any other failure.
2. **Beacon** — mint the lower time bound,
   and put it into the statement that stage 3 writes.
   It runs before the tool touches anything on disk,
   so an explorer outage costs nothing.
3. **Manifest and root** — regenerate `multiproofs/tree-hashes.csv` from the worktree,
   then derive `multiproofs/tree-root.txt` from it.
4. **Sign** the root statement.
5. **Stamp** the root statement and every signature over it, into one bundle.

`--no-stamp` skips stages 2 and 5;
`--no-content-anchor` runs stage 5 over the signatures only.
`--external-signer` moves stage 4 to another device:
the first run stops after stage 3 and names the `.sig` file it waits for,
and the next run checks that signature and goes on to stage 5.
Neither flag skips stage 1,
so `--no-stamp` reaches the network anyway when the tree contains a pending `.ots`.
It seals offline only in a repo that has nothing left to upgrade.

`seal` refuses a repo with no tracked files:
the root of a tree with no files is the same for every empty repo.
So a signature over it would state nothing about this repo.
A repo that has files but no commit yet seals normally
— only `multiproofs/snapshot.txt` is withheld, since there is no HEAD to name.
The same holds for a dirty tree, and a stale snapshot record is deleted rather than left behind.

It is safe to run `init` again.
It creates nothing that already exists,
it names the key that is already registered,
and it exits 0.
If `init` runs again with `--pubkey`,
it adds that key when the trust list does not contain it.
When the list contains it, `init` says so.
A second run with no flags registers the signing key from `git config`.
After the first run, that key is already there.

### Sealing under an explicit key

The signing key comes from `git config user.signingKey` of the target repo.
`seal` has no `--key` flag,
because the signing identity of a repo belongs in its config,
not in each command call.
To seal under a different key, run the steps that `seal` wraps:

```nushell no-run
nu-multiproof init --pubkey ./otherkey.pub          # register it: sign refuses an unregistered key
nu-multiproof tree-hashes                           # regenerate the manifest
nu-multiproof merkle write-root                     # mint the root statement over it
nu-multiproof ssh-sign sign multiproofs/tree-root.txt --key ./otherkey
nu-multiproof ots stamp multiproofs/tree-root.txt   # optional — the time anchor
```

`merkle write-root` does not mint a beacon itself:
the default of its `--beacon` is `none`.
So this chain makes a statement with no lower bound,
unless the signer gives it a token from `beacon latest`.

This is the purpose of `merkle write-root` as a separate command.
`merkle write-root` is the only way to mint `tree-root.txt` without `seal`,
and so without the key of `seal`.
The next step is a plain `ssh-sign sign`.
So add a second signer the same way:
sign the current `tree-root.txt`, and do not make a new root.

Two other goals do not need this path.
The first is to stay offline:
`seal --no-stamp` already skips the calendar post.
So use the manual chain only for the key.
The second is a repo in a different location:
`ssh-sign sign` takes `--pubkeys-dir` but no `--repo`.
So run the chain from inside the target repo.

The cost of this path is state between steps:
if the manifest is regenerated after the signer signs the root,
no signature covers the new CSV.
`merkle verify` finds exactly that,
and reports it as `manifest_root`
— see [Merkle inclusion proofs](SPEC.md#merkle-inclusion-proofs).

### Committing a seal

`seal` does not commit,
and `--propose-commit` does not change that.
It writes the commit into the prompt of the signer with `commandline edit`,
and then it stops.
Nothing runs until the signer reads it, edits it and presses enter.
It removes a different failure:
a seal that goes into a commit called "wip", or that spreads over three commits.
Then the log cannot answer the one question that it should answer
— when was this root sealed.

```nushell no-run
nu-multiproof seal --propose-commit
```

Then the prompt contains this, and it does not run:

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

The proposal is a block with variables, not one long line,
because the message is meant to be edited before it runs
and a body escaped into `\n` inside a quoted argument is the one shape that cannot be edited comfortably.
`$msg` gives the body real lines;
the block uses `$repo` two times.
A separate `add` and `commit` cost nothing:
Nushell throws an error when an external command exits non-zero,
so a failed `add` still stops before `commit`.

The reason for this block shape, and what the block does not sanitize, are under [Committing a seal](SPEC.md#committing-a-seal).

## Exit status

A verdict is a returned value, not an exit code.
`ots verify`, `beacon verify`, `merkle verify` and `ssh-sign verify` all return a record with a `valid` field.
All four **exit 0 whether that field is `true` or `false`**.
So a CI job that only reads the exit code passes on a tampered artifact.

To make a not-valid result exit 1, pass `--fail` to those four commands.
Without it, the command returns the record and the caller decides.
So `--fail` is the flag that turns a report into a gate.

Tests pin two of the four
— "verify --fail errors on invalid signature" for `ssh-sign verify`,
and the `merkle verify` cases in `tests/test_merkle.nu`.
`ots verify --fail` and `beacon verify --fail` behave the same way,
but no test holds them there.

All other failures throw an error, and so exit non-zero, with no flag necessary.
That is the difference between a verdict and a broken run,
and the two never share an exit code:

- A refusal to make a claim at all
  — `merkle verify --signer <fingerprint>` where the trust list contains no such key,
  `merkle prove <path>` where the path is not in the manifest,
  `ots verify` on a proof that is still pending.
- A toolchain problem
  — `ssh-keygen` or `chmod` is not in `PATH`.
- An outage
  — fewer than `--min-sources` explorers answer, or the explorers disagree.
- A race for `<stem>.ots` that `ots stamp` loses.
  The digest is already at the calendar,
  so `ots stamp` puts the assembled proof beside that file,
  and the error names the path.
- `seal --no-stamp` together with `--no-content-anchor`:
  `seal` refuses it before it touches anything.

`nu toolkit.nu test` exits non-zero if any test fails.
That is `--fail` again:
there it is on by default,
and `--no-fail` disables it.

## Verifying without the origin repo

The artifact set is portable.
Put it in a plain directory
— no git, no clone of the origin repo —
with the same layout as `multiproofs/`.
Then point `merkle verify` at it with `--repo`:

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
The manifest and the re-derivation exclude everything under that prefix.
So a proof of the `.` row does not fold its own proof file into the CID that it checks.
At the root, it would do this,
and the bundle would report itself as tampered.

This is a supported contract that a test pins
— not an accident of path handling:
an explicit `--repo` is taken as-is (no git required),
and every lookup is layout-relative to it.
One caveat:
the opportunistic OTS upgrade of `seal` walks only the `multiproofs/ots-timestamps/` of the target repo.
So a `pending` stamp in a bundle stays pending until `ots upgrade` runs on it directly.

A proof of a **directory row** (or of `.`) works the same way.
The bundle then holds one more thing:
the subtree itself, under the `filepath` of the row.
The `content_cid` of a directory commits to every entry under it.
So it can be re-derived only from the files,
and a compact proof cannot replace them.
Away from the origin repo, there is no git index to enumerate from,
so `merkle verify` walks the bundle.
It drops `multiproofs/` and `.git`.
The manifest never covered these two directories,
and they are *inside* the walked tree when the row is `.`.
Because the walk drops `.git`, a bundle can be a clone of the sealed repo.
That is the most usual way that a bundle travels (pinned by "the root row of a bundle distributed as a git repo still verifies").

That walk trusts the bundle for the file list,
and it does not need to:
the sealed `content_cid` checks the list.
Under the proven row, a bundle that drops a file, adds a file, or changes a byte folds to a different CID.
`merkle verify` refuses that bundle.
Tests pin this: "a non-git bundle carrying the sealed subtree verifies a directory row" (the same fixture, which verifies), "a bundle that drops a file from a proven directory is refused", "a bundle that adds a file under a proven directory is refused", and "a non-git bundle carrying the wrong bytes under a proven directory is refused".
The proof does not cover files *outside* the subtree of the proven row, and it never did:
the walk stays in that subtree.
So an unrelated file
— or a stray symlink —
beside it does not turn a genuine proof into a report of a tampered bundle.
In a live worktree, git answers a different question:
which files are untracked build output that the seal never covered.

**Pass `--bundle` for an artifact from a sender.**
Without it, `merkle verify` takes the git arm whenever the target *is* a git repo root
— and a sender can make that true.
A `.git` costs nothing to ship.
If its index lists exactly the sealed paths,
it lets the sender choose the file set.
The same bundle with an extra file under the proven directory answers `valid: true` with that `.git`,
and `valid: false` without it.
`--bundle` ignores any index in the target and always walks.
So the verifier chooses the enumeration, not the artifact (pinned by "a bundle cannot hand itself the git arm by shipping its own index").
Distributing a bundle as a git repo is ordinary,
so this is not an exotic shape.
The flag has no effect for file rows,
because file rows never consult git.

The result reports the arm that ran as `content_enumeration`
— `"git-index"` or `"walk"`, and `null` for a row that consulted no file set.
The two meanings of `content_verified: true` are different claims ("the tracked files are the sealed ones" versus "everything the sender shipped folds to the sealed CID").
So a consumer that keys on `.valid` needs to see which claim it got.
The flag lets a verifier choose the arm;
the field lets it check what it chose.

So `content_verified: "unverifiable"` stays for one case only:
a row that commits to no content at all
— no `content_sha256` and no `content_cid`.
It still blocks `valid`,
because a row whose only commitment cannot be checked must not look like a row that was checked.

## Origin proofs

[`multiproofs/origin-proofs/`](multiproofs/origin-proofs/) contains proofs of how this repository came to exist.
The README of that directory tells the full story.
In brief:

- **`tree-hashes.CCA016A8/`**
  — a timestamp of the extracted subtree (a snapshot of the source repo) in Bitcoin block 939896, with an SSH signature
- **`tree-hashes.93223B2F/`**
  — a bridge stamp:
  the first OTS made from inside this repo after the extraction, Bitcoin block 940583

These are archival artifacts.
The current operational timestamps are in [`multiproofs/ots-timestamps/`](multiproofs/ots-timestamps/).
`SPEC.md` specifies their layout under [Timestamp bundles](SPEC.md#timestamp-bundles).

## Verifying commit signatures

Here, a signature on a commit is occasional, not a policy.
Commits that agents made have no signature,
and the commits signed by hand are spread through the log.
So `git log --show-signature` prints nothing for most of the log.
The commit "revoke claude-code signing key" is one signed commit on which to try the recipe.
Find it by its subject,
because a sha changes each time history is rewritten.
The recipe stays here because `multiproofs/pubkeys/` is exactly the source from which an `allowed_signers` file is rendered.

The verification of an SSH-signed commit has two different checks:

1. **Cryptographic validity**
   — does the signature mathematically match the commit bytes under some public key?
   This check is key-agnostic and needs no trust.
2. **Trust**
   — is that public key one that the *verifier* chooses to recognize as a valid signer?
   This is a policy of the verifier.

Git does not keep the two checks apart:
it refuses to verify SSH signatures unless `gpg.ssh.allowedSignersFile` is set and points to a file that exists.
That file maps principals → keys → namespaces;
it is the **local trust list** of the verifier, not part of a commit.
When the verifier sets it, the *verifier* makes a statement about the keys that it trusts
— the repo cannot make it for the verifier.

`multiproofs/pubkeys/` is the source of truth of this project for who can sign.
Nothing here writes the trust file for the verifier.
That file *is* the statement about the keys that the *verifier* accepts,
so the verifier makes it, not the repo.
The format has one line for each key
— `<principals> namespaces="git" <keytype> <base64>`.
The `*` principal below is collective trust:
the key is in the list of this project, with no personal identity attached to it.

### One-shot inspection

`git -c key=value` overrides the config for one command call only, and keeps no state:

```nushell no-run
let signers = "/tmp/nu-multiproof-signers"
ls --all multiproofs/pubkeys | get name | where ($it | path parse | get extension) == "pub" | each {|f| $"* namespaces=\"git\" (open --raw $f | split row --regex '\s+' | first 2 | str join ' ')" } | str join "\n" | save --force $signers
git -c $"gpg.ssh.allowedSignersFile=($signers)" log --format='%h %G? %an %s'   # G = good, N = unsigned
git -c $"gpg.ssh.allowedSignersFile=($signers)" log --show-signature -1 --grep "revoke claude-code signing key"
```

Start with the first command:
`%G?` marks each commit `G` or `N`.
So it shows that the trust list resolves,
and it also shows the commits that the list can say something about.
`--show-signature -1` on an unsigned commit prints no signature line at all.

`first 2` keeps the key type and the base64 blob,
and drops the comment at the end (`alice@laptop`).
The comment is not part of the trust statement,
and it is different on each machine.

### Per-clone setup

For repeated inspection, write the same file inside this clone's `.git/` and point its **local** git config at it:

```nushell no-run
let signers = $"(git rev-parse --git-dir | str trim)/allowed_signers"
ls --all multiproofs/pubkeys | get name | where ($it | path parse | get extension) == "pub" | each {|f| $"* namespaces=\"git\" (open --raw $f | split row --regex '\s+' | first 2 | str join ' ')" } | str join "\n" | save --force $signers
git config gpg.ssh.allowedSignersFile $signers
```

`.git/config` is inside the `.git/` directory of this clone
— git does not track it, push it or share it with collaborators.
Now a plain `git log --show-signature` resolves without problems.
After each change to `multiproofs/pubkeys/`, render the file again.

### Reading the output

```text
Good "git" signature for * with ECDSA-SK key SHA256:7SOGNZ2C…
```

- `Good`
  — both checks above passed.
- `for *`
  — the matched principal is the `*` that the verifier wrote into the file.
  This principal confirms that the key is in the trust list of the project,
  but it does not attach a personal identity.
  This is the suitable trust statement for the tracked signers of a project
  — collective trust, not individual identification.

One caveat about the source of the keys:
`multiproofs/pubkeys/` travels inside the repo that the verifier examines.
If the verifier renders the trust file from it and then verifies the commits of that repo,
the result proves that the repo agrees with itself.
Anyone can fork, add their own key and re-sign.
To make it an identity check,
compare the fingerprint that git reports with one that the verifier has from a different source.
`merkle verify --pubkeys-dir` exists for the same verifier-side step.

## Limitations

Collected here because each is easy to miss in the section that explains it.

**The work behind a Bitcoin header is not checked.**
`ots verify` recomputes the hash of the header and its merkle binding.
But it reads `bits` from the same header that it examines,
so "the hash meets its own target" proves nothing.
The whole defence is that independent explorers agree on the hash for each height
— see [Verifying a timestamp](SPEC.md#verifying-a-timestamp).

**A trust list that travels inside the artifact proves only self-consistency.**
A default `valid: true` says that the bundle agrees with itself.
Anyone can fork, `init` with their own key and re-`seal`.
A verifier uses `--pubkeys-dir` and `--signer` to state its own policy.

**Three commands take no `--repo`** — `ssh-sign sign`, `ssh-sign verify` and `ots stamp`.
They resolve the default of `--repo` from the current directory,
and no flag overrides it.

**The opportunistic upgrade of `seal` walks only the bundles of the target repo.**
A bundle from a sender keeps its `pending` stamp until the recipient runs `ots upgrade` on it directly.

**No test vector covers a file DAG deeper than two levels** — about 7.9 GB.
The fold there is the same code, but nothing outside this repo pins it.

**A directory that would become a HAMT shard is refused, not approximated.**
That is approximately 6200 files with 8-character names in one directory,
and fewer when the names are longer.
`tree-hashes` stops with an error,
and does not emit a CID that no IPFS client would reproduce.

**The commit proposal is not sanitized for display.**
A repo path that contains ANSI escapes goes into the prompt raw,
and it can repaint the line before the signer presses enter.
The guarantee is that the block parses as one command,
never that it renders honestly.

**Two of the four `--fail` paths have no test** — `ots verify` and `beacon verify`.
Both behave like the two that do, checked by running, but nothing holds them there.

**Eleven of the fifteen bundles committed here carry no endorsement anchor and cannot get one**.
And the two under `origin-proofs/` carry a signature over the `.ots`, not over the snapshot.
`ots stamp` never writes that shape.
These thirteen bundles are history, not examples of the grammar.

## Testing

The tests use [nutest](https://github.com/vyadh/nutest),
which is cloned as a sibling directory.
Run them from the repo root:

```nushell no-run
git clone https://github.com/vyadh/nutest ../nutest
nu toolkit.nu test              # runs tests/; exits non-zero on any failure
nu toolkit.nu test --network    # runs tests-network/ instead — reaches the internet, and
                                # one test writes a permanent public timestamp
```

By default, the suite runs on one thread.
`CLAUDE.md` tells why,
and what the risk of `--threads 0` is.

## License

MIT
