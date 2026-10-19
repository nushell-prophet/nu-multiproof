# nu-multiproof specification

This document gives the mechanics behind `README.md`:
the byte formats, the file layouts,
and what each command reads, writes and reports.
`README.md` says what the tool is for and how to use it.
`README.md` also gives numbers to the five stages of `seal` that this document refers to.

## Signers

`ssh-sign` signs a file with an SSH key.
It also verifies every `.sig` beside a file against the keys in `multiproofs/pubkeys/`,
and it separates "content changed" from "key not registered".
`seal` uses it to sign the root statement,
and `merkle verify` uses it to check that signature.
It also runs alone on any file.

A signer here is a **key fingerprint**:
the SHA-256 of the key blob, 64 lowercase hex.
This fingerprint is the digest that `ssh-keygen -lf` prints as `SHA256:<base64>`.
The fingerprint is written in hex,
so that one form is legal in a filename, in an `allowed_signers` line and on a command line.
`pubkey fingerprint` prints it for a key line.
It is the only name that this project gives to a key:
`init` stores keys as `multiproofs/pubkeys/<fingerprint>.pub`,
the name of a signature is `<file>.<fingerprint>.sig`,
and `--signer` takes the fingerprint.
No part of this name comes from a file name or a key comment,
and no flag chooses it.
So a trust list that files mallory's key as `alice.pub` still shows mallory's fingerprint.

Thus the name of a `.pub` file is only decoration,
and any signer can choose it.
Any signer can rename a registered key with `mv`,
or put their own key into `multiproofs/pubkeys/` as `alice.pub`.
In both cases the principal comes from the bytes inside the file.
The test "a pubkey file name the trust list could never express still signs and verifies" pins this.
But such a name cannot *say* anything:
`alice.pub` is not a claim that alice signed,
and an invisible character makes one name read as another in a diff.
For this reason `init` does not invent a name.

This is not a proof of identity.
A fingerprint names a key, not a person,
and the trust list travels inside the same thing that the verifier examines.
The verifier does the step that binds a fingerprint to a person:
compare the fingerprint with one that the verifier got from a different source.
See [Verifying commit signatures](README.md#verifying-commit-signatures).


## Committing a seal

`README.md` describes what `seal --propose-commit` leaves in the prompt.
Three parts of it are deliberate.
First, the block uses `git -C <root>`,
because `seal --repo` can point at a different repo.
Even in the local repo, the `multiproofs` pathspec resolves against the CWD.
So a bare `git add` fails from any subdirectory.
The test "git is aimed at the sealed repo rather than the current directory" pins the use of `git -C <root>`.
Second, the block uses `add -- multiproofs`, not the paths that `seal` returned.
A seal also *deletes* files in that directory:
it clears a signature over bytes that the regeneration changed.
No result field shows a deletion.
So a proposal that names only the written files would commit a folder where git still holds a cleared signature.
Third, `Signed by` is the principal that `seal` resolved from key material before it signed.
`Signed by` is never a name read back from `<file>.<fingerprint>.sig`.
That is the filename-as-identity shape.
The test "the signer is the principal passed in rather than anything read off a filename" pins the source of `Signed by`.

`to nuon` escapes everything that is interpolated into the block.
The nuon format *is* the string-literal syntax of Nushell itself,
so its serializer already has the job to stay in step with the parser.
A repo path is data,
and the block goes to a prompt where it is ready to run.
So the pinned behavior is the escaping **at its use site**.
The test "a repo root holding a quote and a backslash still commits" seals a repo in a directory.
The name of that directory holds a quote and a backslash.
Then the test runs the emitted block for real.
A test of the escaper alone is not sufficient.
Both calls to it could be replaced with raw interpolation,
and the rest of the suite stayed green.

This does not sanitize the path for display.
A control character in the path reaches the prompt raw.
So a directory with ANSI escapes in its name could repaint the line that the signer reads before the signer presses enter.
This limit is deliberate, not a mistake:
the guarantee is that the block *parses* as one command with one argument,
never that it *renders* honestly.
The repo root is a path that the signer chose, not input from an attacker.

Outside a REPL, `commandline edit` still writes the repl buffer of the engine.
This is harmless, but it is not a no-op.
Only the REPL reads that buffer back.
So in a script the flag has no effect, and it is not an error.
The test "asking for a commit proposal leaves the seal result untouched" pins this.

## Content manifest

`nu-multiproof tree-hashes` writes `multiproofs/tree-hashes.csv`:
one row per git-tracked file, one per parent directory, and one for the repo root `.`.
A file that git marks `export-ignore` gets no row:
the repo keeps it,
and the published tree does not hold it.
Write the pattern as `todo/** export-ignore`;
the form `todo/ export-ignore` marks only the directory, and its files keep their rows.
`tree-hashes` refuses a `.gitattributes` that is itself marked `export-ignore`,
because the manifest then does not hold the rule that shapes it.
A file row names the same bytes in four ways.
`content_sha256` is over the raw bytes.
`content_git_sha1` and `content_git_sha256` are the git blob object in each object format.
These two come from a temp index over the working tree, not from HEAD.
`content_cid` is the IPFS CID v0.
A directory row has no `content_sha256`,
because a directory has no bytes of its own.
Its git columns hold the git tree object,
and its `content_cid` holds the UnixFS directory.
The `.` row carries only the root CID.
The manifest excludes rows under `multiproofs/`,
so it never describes its own proofs.

The git columns are a **lookup key, not an integrity anchor**.
They make it cheap to find a file in a repo,
whatever object format that repo uses.
`content_sha256` and `content_cid` are for integrity.

Every manifest always has both formats,
whatever format the described repo runs.
Most repos in the world are SHA-1,
so a manifest with only SHA-256 would answer none of their `git hash-object` lookups.
Also, no verifier can rely on a column that exists only sometimes.
With both formats, every column is also a function of the content alone.
So the merkle root does not depend on the object format of the repo where the root was built.

The values are git object hashes,
and a reader needs no git to reproduce them.
For a file, the value is `H("blob " + len + "\0" + bytes)`.
For a directory, the value is `H` over the bytes of the git tree object (sorted entries, modes, child hashes).
Here `H` = SHA-1 for one column and SHA-256 for the other.
But `tree-hashes` does not reproduce them that way.
It asks git, in a temporary bare repo that it creates with `--object-format` and points at the real working tree.
That repo answers for the format that the described repo does not run.
So `content_git_sha256` differs from `content_sha256` only by that `blob <len>\0` header.

**Cross-repo checks still use `content_sha256`.**
The raw content hash is the same wherever the file is hosted and however it is stored.
The git columns do not depend on the host, but they have the shape of git.
They say what git *would* call these bytes, and nothing more.

Beside the manifest, `tree-hashes` records which commit that manifest describes:
`multiproofs/snapshot.txt`, one line
— `multiproof-snapshot-v1 <commit>`.
`tree-hashes` writes it **only when the tree it read equals HEAD**,
and a dirty tree deletes any record that an earlier run left.
So a stale line cannot outlive the state that it described.
That condition makes the line checkable instead of a claim.
This is because the manifest excludes rows under `multiproofs/`.
Thus the manifest of the HEAD tree and the manifest of a clean working tree are byte-identical.
Check out the commit that the line names and rebuild,
and the merkle root must match.
The test "the recorded commit rebuilds to the same merkle root in a fresh checkout" pins this.
Nothing signs the line and nothing reads it:
it is provenance for a person or a later tool, never an input to a verdict.
The line has two limits.
A repo before its first commit has no HEAD to name,
so no file appears.
The absence of the file is the normal state, not an error.
And the manifest is a function of the *checkout*, not of the commit.
A checkout filter (`core.autocrlf`, `.gitattributes`, git-LFS) is machine configuration that the commit does not carry.
So two checkouts of one commit can give different hashes.
This fails safe:
a verifier then says "does not match", never the reverse.
Through `--propose-commit`, the body of the seal commit carries the same commit.
The commit body may read "plus uncommitted changes" only there.
A commit message is a channel for humans,
so an unchecked claim is allowed in it.

Two commands show it without the CSV.
`tree-hashes --echo` returns the table and writes nothing
— also no snapshot record, because it saves no manifest for a record to describe.
So it is the safe one:
use it to see what a seal would record.
`tree-hashes root-cid` returns only the CID of the `.` row,
but it is **not** read-only:
it regenerates the manifest first.
So a run of `root-cid` after a seal can leave a CSV that no signature covers.
That is exactly the drift that `merkle verify` reports as `manifest_root`.

Nushell computes the CIDs in-process:
no `ipfs` daemon or CLI takes part,
and there is only one manifest shape to sign.
Content over 256 KiB is chunked and folded into a UnixFS DAG in the same way as the reference client does it.
So `content_cid` is the CID that `ipfs add` reports for that file,
and the `.` row is the CID of the whole tracked tree.
Reference: `nu-multiproof/_cid-helpers.nu`.
The conformance vectors are in `tests/test_cid-v0.nu`.
They were recorded from the reference client.
The vectors cover single files from empty up to one full 262144-byte chunk, and a multi-chunk file.
They also cover a two-level DAG (175 chunks), a directory tree, and the directory at the HAMT threshold.
The chunked vectors and the directory vectors were recorded with ipfs 0.42.0.
The CID of the empty directory is publicly known, not recorded.
No vector covers a file DAG deeper than two levels
— 175 full branches, about 7.9 GB.
The fold there is the same code,
but nothing outside this repo pins it.

There is one limit, and at that limit the tool fails loudly and does not lie:
IPFS changes a directory to a HAMT shard when its entries exceed 256 KiB by the estimate of kubo.
The estimate is name length + 34 bytes per entry.
That is about 6200 files with 8-character names in a single directory,
and fewer when the names are longer.
This code builds only basic directories,
so `tree-hashes` refuses such a directory.
It does not emit a CID that no IPFS client would reproduce.

The root CID names content, but it does not publish it.
Nothing here talks to IPFS,
so the tree is available through the network only if the signer adds it.
Over a directory that holds exactly the files with a row, `ipfs add -r --hidden --cid-version=0 --raw-leaves=false --hash=sha2-256 --chunker=size-262144` reproduces the `.` row (`--hidden` because `ipfs add` skips dotfiles otherwise).

## Merkle inclusion proofs

`multiproofs/tree-hashes.csv` is a flat manifest.
If a signature covered all of it,
then an inclusion proof for one file would require the verifier to keep the entire CSV.
The merkle layer solves that problem.
The CSV stays the authoritative catalogue.
But `seal` also derives a binary merkle tree over its rows,
and it signs and stamps only the one-line root statement (`multiproofs/tree-root.txt`).
A consumer then holds one row plus ~log2(n) sibling hashes
— for a million files, ~20 hashes instead of a million rows.
(The trees of git itself cannot do this job.
They branch wide,
so a path through them lists every sibling in each directory.
The path grows with the width of the directory and leaks the filenames of the neighbors.)

The root also authenticates the whole catalogue, indirectly.
The root comes from every row,
so anyone who holds the full CSV can rebuild the tree and must get the signed root.
If one row changes, the two roots are different.
For this reason `seal` itself does not sign the CSV.
`ssh-sign sign multiproofs/tree-hashes.csv` still works.
Exactly the same rule clears a signature over the manifest and a signature over the root statement.
A manifest signature stays after a reseal that regenerates identical bytes,
and it goes when the bytes change.
The test "a deliberate manifest signature survives an unchanged reseal" pins this.
One limit is deliberate:
the root commits to the parsed row data, not to the exact bytes of the CSV (column order, quoting style).
Leaf serialization uses the parsed field values,
because CSV quoting is not canonical.

The full artifact set of a consumer:
the proof file (`merkle prove <filepath>`), `tree-root.txt`, a `.sig` over it, and the pubkey of the signer from `multiproofs/pubkeys/`.
For the time anchors, the set also holds the `tree-root.*` OTS bundle.
That bundle carries both anchors:
`<stem>.ots` dates the content, and `<stem>.<ext>.<fingerprint>.ots` dates the endorsement.
See [Dating the endorsement](#dating-the-endorsement).

By default, the check uses the trust list inside the target
— for a portable bundle, the `multiproofs/pubkeys/` of the bundle itself.
Thus a default `valid: true` says that the artifact set is internally consistent,
not that the signer that the verifier expects endorsed it.
Anyone can fork the repo, `init` with their own key and re-`seal`.
`--pubkeys-dir` points the check at a list that the verifier controls.
`--signer <fingerprint>` makes the check narrower:
it then needs a valid signature from that one key, not from any registered key.
A principal is the fingerprint of the key itself,
so `--signer` is a statement about key material.
`--signer` holds even over the list of the bundle itself.
A bundle can give its key files any name,
but the principal that the list shows still comes from the bytes inside them.
So a bundle cannot make its key answer for the key that the verifier expects.
The test "a bundle cannot file one key under the fingerprint of another" pins this.
But a bundle *can* omit the key completely.
A `--signer` for which the trust list holds no key is an error, not `valid: false`.
"alice did not sign this" is a claim,
and without alice's key the verifier cannot make it.
The test "signer with no matching key in the trusted dir is an error and not invalid" pins this.
Which fingerprints count is still a statement that only the verifier can make
— the same verifier-side policy that [Verifying commit signatures](README.md#verifying-commit-signatures) describes.

`merkle verify` folds the proof to the signed root,
and it checks the SSH signatures over the root statement.
If the proven `content_sha256` is present, the command re-hashes the on-disk file against it.
The command also reports the OTS anchor.
If the embedded root of a proof differs from the signed root, the proof is for a different seal.
Such a proof fails loudly and does not report invalid.

It prints a summary for humans and returns a record of twelve fields.
Four of them decide the verdict:

- `structure_valid` — the proof path folds to the signed root. **Blocks `valid`.**
- `manifest_root` — the root rebuilt from `multiproofs/tree-hashes.csv`, or `null` if there is no CSV.
  A value that differs from `root` **blocks `valid`**; `null` does not.
- `signatures` — one row per `.sig` beside the root statement, `{signer, valid, sig}`.
  If no signature is valid, that **blocks `valid`**,
  and with `--signer` the valid signature must come from that fingerprint.
- `content_verified` — a state from the table below.
  Only `true` passes, so every other value **blocks `valid`**.

`valid` is the conjunction of these four.
The other seven fields are only a report, and none of them can lower `valid`
— an undated seal is not an invalid seal:

- `root` — the root that the signed statement holds.
- `leaf` — the manifest row that the proof is about, with all five columns.
- `content_enumeration` — `"git-index"`, `"walk"`, or `null` for a row that used no file set.
- `ots` — `{status, ots, height}`, where `status` is `absent`, `pending` or `anchored`.
  A new seal stays pending until Bitcoin confirms it, which takes hours or days.
- `beacon` — the token that the statement carries; the command reports it and never checks it.
- `endorsements` — one row per signature that verified, `{signer, status, ots, height}`.
- `error` — the first reason why `valid` is false, or `null`.
  It is a fuller sentence than the one-word verdict of the printed summary, not the same string.

The content leg answers with a state, not a boolean,
and **only `true` passes**
— every other value blocks `valid`.
A row whose commitment could not be checked must never read as a row that passed the check:

- `true` — the bytes on disk match what the leaf attests.
- `false` — they do not: the file changed, or the proof describes different bytes.
- `"missing"` — there is nothing at that path on disk.
- `"symlink"` — a symlink where the catalogue describes a regular file.
  The check for a symlink comes before the check for existence,
  so a broken link does not read as missing.
- `"outside"` — the path resolves out of the repo, through a parent directory that is a symlink.
- `"directory"` — a file row that lands on a directory.
- `"unverifiable"` — the leaf carries no commitment at all
  — neither a `content_sha256` nor a `content_cid`, so there is nothing to re-derive.

If `multiproofs/tree-hashes.csv` is there,
`merkle verify` also rebuilds the root from it and reports that root as `manifest_root`.
A value that differs from the signed `root` blocks `valid`.
The statement is a claim about that catalogue,
and the two are written in separate steps.
An interrupted `seal`, or a bare `tree-hashes` run after it, leaves a CSV that no signature covers.
At the same time, old proofs still fold to the old statement.
A portable bundle carries no CSV,
so `manifest_root` is `null` there, and nothing is cross-checked.
(Pinned by the test "a manifest that no longer yields the signed root is caught".)

The verifier can still check a proof of an **older seal** in place with `--multiproofs-dir`.
Point it at a directory that holds the `tree-root.txt` of that seal and its `.sig` files.
(A CSV is optional. If a CSV is present, it is cross-checked.)
`--repo` still names the live content.
The command reads the signed statement, its signatures and the manifest leg from the named directory.
The default trust list and the discovery of OTS stamps stay with `--repo`.
This is because a snapshot freezes the statement and the signatures, never the keys.
Also, the stamp archive is cross-seal, with discovery by content hash.
(Pinned by "a proof of an older seal verifies against that snapshot of the seal", "the manifest cross-check follows the multiproofs dir and not the repo", "a planted signature over another statement does not endorse the snapshot" and "an anchor in the live archive dates an older seal verified via its snapshot".)

## Tree specification

This section pins the tree exactly,
so an independent implementation reproduces the root from the same CSV (reference: `nu-multiproof/_merkle-helpers.nu`, test vectors: `tests/test_merkle.nu`).

- **Leaves**: all CSV rows (directory rows and the `.` root-CID row included), sorted by `filepath`.
  The sort is byte-wise lexicographic order over the UTF-8 path bytes, with no locale and no Unicode normalization.
  Duplicate filepaths are a hard error.
- **Columns**: exactly the five below, no more and no fewer.
  A sixth column is refused, not ignored.
  The leaf bytes would not show that it was there,
  so two manifests that differ only in a dropped column would share a root.
- **Leaf bytes**: the five parsed field values (RFC 4180 CSV parsing, not raw lines) joined with `\n`:
  `filepath \n content_sha256 \n content_git_sha1 \n content_git_sha256 \n content_cid`.
- **Charset constraints** (make the `\n`-join injective; reject, never normalize):
  `filepath` is non-empty and contains no bytes < 0x20;
  `content_sha256` is empty or 64 lowercase hex;
  `content_git_sha1` is empty or 40 lowercase hex;
  `content_git_sha256` is empty or 64 lowercase hex;
  `content_cid` is empty or a base58btc CIDv0 (`Qm` + 44 chars).
- **Path containment**: `filepath` has no leading `/` and no `..` component.
  `verify` joins it onto the target directory and reads it.
  So either form would let a bundle prove a file that it does not contain
  — or a file that belongs to the verifier.
  `git ls-files` emits neither,
  so no legitimate path is refused.
  Bare `.` is legal on purpose:
  it is the root-CID row.
- **Symlinks**: refused, never followed.
  If the code followed one, it would take `content_sha256` and `content_cid` from the target.
  But the git columns would stay the git blob of the link string.
  So one row would describe two objects.
  Also, a link that points outside the repo would pull foreign content into the catalogue.
  `tree-hashes` gives an error and names the paths at fault.
- **Hashing** (RFC 6962 domain separation): leaf hash = `sha256(0x00 ++ leaf_bytes)`;
  inner node = `sha256(0x01 ++ left ++ right)` over the raw 32-byte child hashes.
- **Shape** (RFC 6962 MTH): split the leaf list at the largest power of two below n, and recurse on both halves.
  No padding, no last-leaf duplication.
  n=1: root = the leaf hash.
  n=0: root = `sha256("")` = `e3b0c442…`.
- **Proof steps**: `side` names the position of the **sibling**, in leaf-to-root order:
  `side: right` → `acc = sha256(0x01 ++ acc ++ sibling)`;
  `side: left` → the sibling goes first.
  The check of the encoding comes before the fold:
  `hash` must be a JSON *string* of 64 lowercase hex.
  A number, or hex with any uppercase, is refused — not coerced.
  `side` must be exactly `left` or `right`.
  This is the most common interop bug in merkle verifiers,
  so here it fails loudly and does not fold something plausible.
- **Root statement**: exactly `multiproof-merkle-v4 <64 lowercase hex> <seq> <prev> <beacon>` + one trailing `\n`.
  The statement form (not a bare hash) prevents a replay of the signature in another hash-signing context.
  `seq` is a decimal count that starts at 0, with no leading zeros.
  `prev` is the root that this seal replaces
  — or the literal `genesis`, which pairs with `seq 0` and with nothing else.
  `beacon` is either the literal `none` or `bitcoin:<height>:<64 lowercase hex block hash>`
  — the lower time bound of the seal; see [The lower bound](#the-lower-bound) below.
  The height is a decimal count with no leading zeros, for the same reason as `seq`.
  The reason is that a signature covers bytes,
  and two spellings of one number are two byte strings that state one value.
  The counter has this reason:
  a root says what a tree held, never which seal it was.
  Also, `multiproofs/` keeps only the live statement.
  So "does this seal follow that one" had no answer outside git history.
  The counter counts roots, not runs.
  A new derivation of an unchanged tree writes the same bytes.
  So a reseal that changes nothing leaves existing signatures valid (the rule stated above for the manifest signature).
  Note what the number is worth.
  `multiproofs/` is outside the manifest,
  so `seq` is not under the merkle root.
  `seq` rests on the signature over these bytes and on their OTS anchor.
- **Reading it back**: `merkle read-root <file>` parses a statement file and returns `{root, seq, prev, beacon}`
  — one field per element of the grammar above, `beacon` included.
  It exists so that a consumer that walks seal snapshots does not keep a second copy of the format above.
  The parser is in `_merkle-helpers.nu`, which is internal.
  The path is required, and it can name any statement file, the live `multiproofs/tree-root.txt` included.

## Timestamp bundles

This section describes what `seal` writes under `multiproofs/ots-timestamps/`,
what `seal status` reads back from it,
and the two directions of time that a bundle can bound.
None of this is specific to the archival `origin-proofs/` directory.

### Bundle contract

Three flags decide where a stamp goes and where its bytes come from.
`ots stamp --out-dir <dir>` is the directory where the command creates bundles;
`--into <bundle>` is one bundle that already exists, and this stamp joins it.
The command refuses the two flags together, before the calendar post,
because they name different destinations.
`--response-file <file>` makes the proof from a calendar answer that is already on disk,
and does not post the digest.
This is the only way to run this path without a permanent public write.
For the same reason, `seal --response-file` gives the flag to every stamp in stage 5.
`ots upgrade --calendar <url>` sends the request to that calendar, not to the calendar that the proof names.
The reason: the URL in the file is attacker input,
and the URL on the command line is a local decision.
`ots upgrade --response-file` is the same offline seam as above.

`<stem>` is the name of the stamped file without its extension.
`<hash-prefix>` is the first 8 hex digits of its sha256, in uppercase.
The digits are uppercase because Nushell's `encode hex` gives uppercase,
and because the prefix is a directory name, not a value that the tree specification constrains.

An OTS bundle directory (`multiproofs/ots-timestamps/<stem>.<hash-prefix>/`) is self-contained provenance.
The directory holds every file that is necessary to assert one claim:
*"content C existed at time T, anchored to Bitcoin block B, and signer X endorsed C by time T2"*.
The directory has no reference to anything outside it.
Read each anchor separately.
This is because a proof commits to the hash of one file and nothing else.
So the anchor of the snapshot dates C, and the anchor of a signature dates that endorsement.
One seal moment is one bundle:
`seal` stamps the root statement and every signature over it *into the same directory* (pinned by "seal puts the root statement and its signature and both anchors in one bundle").
So the two claims sit side by side, not in two directories where neither directory could make both claims.
With `--no-content-anchor`, `seal` makes the same directory from the same name, with the same frozen copy.
But this directory has no `<stem>.ots` in it (pinned by "seal --no-content-anchor dates every signature and leaves the content undated").
So both cases give one bundle, and a reader of this tree does not need a second layout.

- `<stem>.<ext>`
  — frozen content snapshot (the bytes of the stamped file at stamp time)
- `<stem>.ots`
  — the timestamp over the hash of the snapshot.
  A fresh `ots stamp` writes a *pending* calendar attestation here.
  When a block confirms it, hours or days later,
  `ots upgrade` replaces it in place with the Bitcoin-anchored attestation.
  If `ots upgrade` runs on a proof that is already anchored, `ots upgrade` returns `{status: already-verified, path}` and rewrites nothing.
  So stage 1 of `seal` can walk every `.ots` in the tree and needs no special case for the proofs that it upgraded before.
  Until that upgrade runs, the bundle carries the content and the signature, but not the anchor yet.
  So the bundle cannot make the "at time T, in block B" half of the claim above
- `<stem>.<ext>.<fingerprint>.sig`
  — SSH signature over the snapshot.
  The stamp copies it in at stamp time,
  so that it survives a later `seal` that replaces the live sig.
  A reseal replaces the live sig only when the bytes of the root statement changed,
  or when the key is a randomized key (ECDSA, ecdsa-sk).
  A randomized key gives a different signature for the same bytes each time.
  A reseal over an unchanged tree under a deterministic key leaves the live `.sig` byte-identical.
  The stamp copies every signature that sits beside the stamped file, and the bare `<stem>.<ext>.sig` form too.
  So a bundle carries one signature per signer, not only one (pinned by the test "stamp snapshots every signature beside the file it stamps").
  `seal` signs before it stamps.
  So its bundles always carry at least its own signature (pinned by "seal puts the root statement and its signature and both anchors in one bundle")
- `<stem>.<ext>.<fingerprint>.ots`
  — the timestamp over the hash of *that signature*,
  so the bundle dates the endorsement and not only the content.
  The naming rule is the same as for `<stem>.ots`, one level in.
  Remove `.ots`, and what remains is the name of the sibling that the `.ots` file proves.
  `ots stamp <sig> --into <bundle>` writes it.
  This command joins a bundle that exists.
  The command does not derive a directory of its own (pinned by "stamp --into joins the named bundle instead of deriving one").
  The bundle must already exist *as a real directory*.
  Otherwise a typo would create a directory outside this grammar (pinned by "stamp refuses an --into bundle that does not exist").
  Also, a regular file or a symlink to a directory would otherwise lose the proof after the command already posted the digest (pinned by "stamp refuses an --into that exists but is not a real directory").
  The command also refuses to take a `<stem>.ots` name when that proof covers a *different file still in the bundle*.
  This is because two files can share a stem.
  Only one of them can own the name (pinned by "stamp --into refuses to take the ots name that another file proof holds").
  The command also refuses to take the name when it cannot read the incumbent proof at all.
  This is because a proof that cannot be placed cannot be shown safe to archive (pinned by "stamp --into refuses when the incumbent proof cannot be read").
  The command does *not* refuse a superseded proof of the same name.
  A new signature with a randomized key (ECDSA, ecdsa-sk) makes new signature bytes under the same `.sig`.
  So a second `seal` over unchanged content re-anchors that signature.
  That `seal` also archives the previous proof (pinned by "a second seal over unchanged content re-anchors the new signature")
- `<stem>.<YYYYmmdd-HHMMSS>-<8 hex of its own sha256>.ots`
  — a previous proof of the same content.
  The re-stamp that replaced this proof archives it under this name.
  The archived proof has the same content, but a different nonce and calendar response.
  So the archived proof is an independent attestation, and it is worth keeping.
  Two stamps can occur in one second.
  The hash in the name then prevents a collision of archive names (pinned by the test "rapid re-stamps each keep their own proof")
- `<stem>.<YYYYmmdd-HHMMSS>-<8 hex of its own sha256>.ots`, **written by a failed stamp**
  — a proof from a stamp that cannot write `<stem>.ots` (another stamp won the race).
  The stamp does not drop the proof that this run assembled, but parks it beside that file.
  This is because the nonce that binds the proof to this file exists only in that run.
  The name has the same shape as the archived form above.
  So nobody can tell the two forms apart on disk.
  Both are genuine proofs of the content of the bundle,
  and that is why `merkle verify` finds proofs by content, not by name.
  The command still exits non-zero and names the path

The command writes one more form **outside** any bundle, directly under `multiproofs/ots-timestamps/`:

- `<stem>.<hash-prefix>.rejected-<YYYYmmdd-HHMMSS>-<8 hex of its own sha256>.ots`
  — a calendar answer that did not parse into a readable proof.
  The command creates no bundle,
  and these bytes are intentionally not a proof.
  The command keeps them because the digest already reached the calendar,
  and without these bytes nobody can recover the nonce.
  The reference `ots` CLI reads constructs that this parser refuses (forks, for one).
  So recovery from these bytes may still be possible (pinned by the test "rejected stamps in the same second each keep their nonce").
  With `--into`, these bytes go to the *parent* of the bundle (pinned by "a rejected response under --into lands outside the bundle").
  A relative `--into` gives the same result (pinned by "a rejected response under a relative --into is still parked and not lost").
  The reason is the same:
  a bundle is the one place where bytes that are not a proof must not be mistaken for a proof

`seal` makes this layout automatically.
The next `seal` writes `multiproofs/tree-hashes.csv` again,
and signs `tree-root.txt` again when its bytes changed.
Previous bundles stay intact, because the frozen copy and its sig are already in them.
Each new seal makes one `tree-root.*` bundle that holds the root statement, its signatures and an anchor for each of them.
`seal` does not sign or stamp the manifest any more.
This is because the root statement comes from every manifest row.
So the signature and the Bitcoin anchor of the root statement cover the full CSV.
Archival `tree-hashes.*` bundles (including `origin-proofs/`) stay valid as they are;
the bundles from the transition period may also carry a CSV sig.

The bundles committed to this repo are history, not examples,
and they show how the layout arrived in stages.
Every `.sig` in them now carries a fingerprint.
But the older ones had names from a key *file*, until a rename in place changed them.
One ECDSA-SK key had two names (`maxim-uvarov2` and `id_ecdsa_sk_rk`).
The fingerprint principal exists to remove that double identity.
The rename changed nothing that a verifier reads.
A label is not part of the signed bytes,
and the principal comes from key material through `find-principals`.
Two things in these bundles do not match the grammar above, and a rename cannot fix them.
The `origin-proofs/` bundles carry a signature over the **`.ots`**, not over the frozen snapshot.
Someone added this signature by hand after the stamp.
`ots stamp` never writes this shape, because `ots stamp` copies the signatures that sit beside the file it stamps.
And only four `tree-root.*` bundles hold an endorsement anchor.
Three of them are `884CE56B`, `9DE3B2AB` and `70CB00B5`, sealed in August 2026.
The fourth is `ACAC25F0`, the live seal, whose anchor is still pending.
The other eleven have no endorsement anchor and cannot get one.
This is because a stamp made today would date those older signatures to today.
The folder would then look as if the signatures had their dates at seal time.

### Reading the folder

`nu-multiproof seal status` reports every bundle in one table.
So to answer "is this sealed, and is it dated yet", the signer does not need to read directory names or run `ots info` by hand.

It takes `--repo`.
The default is the nearest directory that holds `multiproofs/`,
from the current directory up to the git root.
So a repo that is a subdirectory of a larger repo gets its own report when the command runs inside it.
A repo with no bundles returns an empty list, which prints nothing.

This is the output for this repo.
The `bundle` column shows only its last path segment, so that it fits (the real value is repo-relative, `multiproofs/origin-proofs/tree-hashes.93223B2F` and so on).
Rows 2 to 7 are not shown:

```text
╭────┬──────────────────────┬─────────────────┬─────────┬─────────────────┬─────────┬─────────────────╮
│  # │        bundle        │      file       │ current │     content     │ signers │    endorsed     │
├────┼──────────────────────┼─────────────────┼─────────┼─────────────────┼─────────┼─────────────────┤
│  0 │ tree-hashes.93223B2F │ tree-hashes.csv │ false   │ anchored 940583 │       1 │ absent          │
│  1 │ tree-hashes.CCA016A8 │ tree-hashes.csv │ false   │ anchored 939896 │       1 │ absent          │
│ …  │ …                    │ …               │ …       │ …               │ …       │ …               │
│  8 │ tree-root.050186F7   │ tree-root.txt   │ false   │ anchored 958319 │       1 │ absent          │
│  9 │ tree-root.25A4101E   │ tree-root.txt   │ false   │ anchored 958319 │       1 │ absent          │
│ 10 │ tree-root.70CB00B5   │ tree-root.txt   │ false   │ anchored 964392 │       1 │ anchored 964392 │
│ 11 │ tree-root.884CE56B   │ tree-root.txt   │ false   │ anchored 961656 │       1 │ anchored 961656 │
│ 12 │ tree-root.9DE3B2AB   │ tree-root.txt   │ false   │ anchored 963127 │       1 │ anchored 963127 │
│ 13 │ tree-root.A1E01AFA   │ tree-root.txt   │ false   │ anchored 959037 │       1 │ absent          │
│ 14 │ tree-root.ACAC25F0   │ tree-root.txt   │ true    │ pending         │       1 │ pending         │
╰────┴──────────────────────┴─────────────────┴─────────┴─────────────────┴─────────┴─────────────────╯
```

Row 14 is the seal in force,
and both of its anchors still wait for Bitcoin.

`current` is a byte compare against the live artifact of that name under `multiproofs/`.
`current` is the only thing that separates the seal in force from the archive.
On disk, they look the same (pinned by "seal status marks only the bundle whose snapshot is the live artifact").
It is `null`, not `false`, when no live artifact has the same name.
`false` says "a later seal superseded this".
A bundle over another file was never in that race (pinned by "seal status reports current as null when no live artifact shares the name").
`content` and `endorsed` are `absent`, `pending`, or `anchored <height>`.
`endorsed` is one such value per signature in the bundle, joined with commas into a single string.
So `where endorsed =~ anchored` works over a bundle with several signers.
The number is the Bitcoin block that the proof binds to.
The block number is the only time that an `.ots` carries.
The wall-clock time of a block is in the block header, and no proof holds a header.
So a date needs `ots verify`, which fetches headers and cross-checks explorers.
`status` stays offline and reports the height (pinned by "seal status reports the block height an anchor binds to").
Two seals can share a block, as rows 8 and 9 do:
a calendar aggregates every digest it receives into one merkle tree per transaction.

`seal status` finds bundles by the proofs that they hold, not by a name pattern, across the whole `multiproofs/` tree.
So archival subtrees like `origin-proofs/` appear too.
The operational scan of `merkle verify` does not cover them (pinned by "seal status reports a bundle in an archival subtree and not just ots-timestamps").
`seal status` lists real directories only.
So it does not list a bundle behind a symlink (pinned by "seal status does not list a bundle behind a symlinked directory").
`seal status` also skips a parked rejected calendar answer.
It does not report that answer as a broken proof (pinned by "seal status says nothing about a parked rejected calendar answer").
In the same way, the snapshot that a row names is the file that a proof in that bundle *commits to*.
So a stray file in a bundle is not mistaken for its content.
When a bundle holds two stamped files that are not signatures, the file that the bundle is *named* after wins.
The bundle exists because of that hash (pinned by "seal status names the file the bundle is keyed by when it holds two").
`seal status` skips symlinks inside a bundle and does not follow them.
The bytes behind a link are not the bytes that the name describes
(pinned by "seal status reports a bundle holding symlinks instead of failing").

`endorsed` is empty when `signers` is 0.
Otherwise, `endorsed` has one entry per signature, in the sorted order of the signature files (pinned by "seal status reports one endorsement entry per signature").
A bundle whose only stamped content is a signature reads `file: null`, `content: absent`, `signers: 1` and a dated `endorsed`.
Such a bundle carries an endorsement and its date, but no content snapshot.
`signers` is what makes it different from a bundle that holds nothing (pinned by "seal status reports a signature-only bundle as an undated-content endorsement").
Two layouts give this reading.
One is a bundle with no frozen copy at all.
The other is the bundle that `seal --no-content-anchor` writes, which has a frozen copy but no proof over it.
`file` names the snapshot that a proof in the bundle commits to,
so `file` does not name a frozen copy that has no stamp.

It is **not** a verdict.
It checks no signature.
So `signers` counts signature *files*.
The report never says that a signature is valid or who made it.
A name on disk is not evidence of a signer,
and that is the whole reason why a principal is the fingerprint of a key.
Use `ssh-sign verify` or `merkle verify` for that.

### Dating the endorsement

An OTS proof commits to the hash of one file.
So "when did this content exist" and "when was it endorsed" are two claims, and they need two stamps.
An SSH signature has no timestamp field.
So if only the root has a stamp, a `.sig` made today can go into a year-old bundle, and nothing on disk contradicts it.

For this reason, step 5 of `seal` stamps `tree-root.txt` **and every signature beside it**, all into the bundle of the root statement:

- The stamp over the sha256 of `tree-root.txt` claims that the content existed by T;
  `merkle verify` reports it as `ots`.
- The stamp over the sha256 of a `.sig` over that file claims that the endorsement existed by T;
  `merkle verify` reports it as one row in `endorsements`.

Both stay checkable: the verifier hashes a file that it already holds,
and neither needs key material.
`merkle verify` returns one `endorsements` row for each signature that verified, `{signer, status, ots, height}`,
with the same `absent | pending | anchored` values as `ots`;
`height` is the Bitcoin block, and it is null while the proof is pending.
When there are several anchors of the same bytes, the reported anchor is the one with the **lowest** block.
The claim is "existed no later than T",
so the earliest anchor is the strongest, and the others follow from it.
`merkle verify` and `seal status` share the helper that picks the anchor.
So one test pins the rule once, under the other command ("seal status reports the earliest anchor when a bundle holds several").
`merkle verify` matches a stamp to its signer by the hash of the signature file, never by a `.sig` name.
A signature that did not verify gets no row at all.
A date on bytes says when they existed,
never that they endorse anything.
A real signature over this root by a key that the trust list does not hold is exactly that case.
Such a signature is cryptographically correct and stamped.
But it is still not an endorsement that anyone here trusts (pinned by "a dated signature by an unregistered key is not an endorsement").

The loop runs over `sig-files-for`, so a **co-signer is dated for free**.
Sign `tree-root.txt` out of band with a registered key.
Then the next `seal` stamps that signature together with its own signature (pinned by "each signature gets its own dated endorsement").

Why two stamps, and not one object that names both files by digest?
An OTS calendar aggregates every digest it receives into one merkle tree per Bitcoin transaction.
So the second post costs nothing on-chain.
Such an object would only implement that aggregation again, one layer up.
The object would also add an artifact, a grammar, a parser, and a limit per signer that the loop above does not have.
Why not stamp the signature *alone*, which dates the content transitively:
that makes the most durable claim depend on the most fragile claim.
The content time would then not be a bare hash compare any more.
The content time would need the pubkey, `ssh-keygen`, and a key type that OpenSSH still reads.
These are three things that can rot where a hash cannot.
So a bundle that keeps a good content anchor without key material today would then have none.

`seal --no-content-anchor` takes that trade on purpose:
it skips the stamp of the root statement and anchors only the signatures.
So the seal moment makes one claim, not two.
Why the option exists at all:
a bundle can carry an anchor over `tree-root.txt` **and** an anchor over a signature over it.
Such a bundle does not say which anchor dates the statement.
The bundle also does not say what a difference between the two anchors means (content in block 100, endorsement in block 200).
And the bundle does not say whether verification needs both anchors, either or neither.
Nothing in the bundle answers these questions.
On disk, neither anchor comes from the other.
So each reader decides alone, plausibly and differently.
Both readings verify green,
so nothing corrects the drift.
A caller whose main claim is "S endorsed this by block N" always passes the flag, and so removes those three questions.
One such caller is nu-cybergraph, where a link *is* an assertion by a signer.
nu-cybergraph exposes no option of its own.
The default does not change,
because the paragraph above is real:
an archive that must stay checkable without key material wants the content anchor.
Calendar traffic is not a cost in either case.
The aggregation above makes the second post free.
So to drop the second post saves nothing on-chain and almost nothing on disk.
What the readers then say:
`merkle verify` reports `ots: absent`.
`seal status` reports the bundle as `file: null`, `content: absent`, `signers: 1` with a dated `endorsed` (pinned by "seal status reports a --no-content-anchor seal as an undated-content endorsement").
`seal` refuses `--no-stamp` and `--no-content-anchor` together.
One skips step 5, and the other runs it over the signatures only (pinned by "seal refuses --no-stamp together with --no-content-anchor before touching anything").

A date on the endorsement is worth having when a signature must outlive its key.
After a compromise and revocation at time R, only a signature that a proof dates before R still means anything.
The same argument covers key rotation across a long archive.
It also shows which of several co-signers endorsed first.
Some uses need to date content alone:
prior art, the order of two seals, proof that a snapshot falls inside a retention window.
For these uses, the stamp of the root itself already gives the answer,
and the signature stamps add nothing.

One direction this does *not* give:
OTS bounds a time only from above ("no later than T"), never from below.
That is the purpose of the beacon — see [The lower bound](#the-lower-bound) below.

The two `origin-proofs/` bundles do the reverse
— a signature over the `.ots`, not a stamp over the signature (see the note above).
A signature over a proof adds no time,
because the authority of the proof is the chain;
read these bundles as history.

### The lower bound

An OpenTimestamps proof says that the content existed no LATER than a block.
Nothing in it says that the seal is not older.
An SSH signature carries no time at all.
So a statement written today fits a bundle from last year, and nothing on disk contradicts it.

A beacon closes that direction.
A beacon is a public value that nobody could know before a fixed moment.
`seal` writes one beacon into the bytes it signs:
the fourth field of the root statement, `bitcoin:<height>:<hash>`.
The claim is then simple —
this statement did not exist before that block was mined,
because nobody could name its hash earlier.

The two anchors bracket the seal:
the beacon blocks backdating,
and the OTS stamp blocks post-dating.
The claim is only as tight as the gap between the two blocks.

```nushell no-run
use nu-multiproof/
# what seal will embed: the cross-checked block, six deep
nu-multiproof beacon latest
# check a statement's bound against Bitcoin
nu-multiproof beacon verify multiproofs/tree-root.txt
```

The source is a Bitcoin block, six blocks below the chain tip.
The source is Bitcoin and not a randomness beacon such as NIST's or drand.
This is because Bitcoin is the only chain data that this repo already trusts and already cross-checks:
`beacon` asks independent explorers to agree on the height to hash mapping,
and that is the trust argument of `ots verify`, unchanged (see [Verifying a timestamp](#verifying-a-timestamp)).
Another source would add a second trust root, a second parser and a second outage story
for a claim that is not stronger.
The beacon is six blocks below the tip, not the tip itself,
because a tip block can become orphaned.
If that happens, the explorers serve a different hash at that height.
Then nobody can verify a beacon made from that block for the life of the seal.
That is a permanent break, in exchange for about one hour of tightness at the lower end.

Both numbers are defaults, and both commands take the same explorer pair as `ots verify`.
`beacon latest --depth <n>` mints from `n` blocks below the tip; the default is 6.
`--sources` replaces the explorer list and does not add to it, on `beacon latest` and `beacon verify` alike,
so name every explorer to ask.
`--min-sources` is how many explorers must answer before the command asserts a result; the default is 2 on both.
With `--min-sources` lowered to 1, the bound rests on a single responder.
That responder is the one party that the cross-check exists not to trust.

A beacon mint uses the network, the same as the calendar post,
so the same flag controls it:
`seal --no-stamp` seals offline and writes `none`, which is a legal statement.
There is no `--no-beacon`.
If the caller asked for a beacon and no explorer answers,
`seal` throws before it rewrites anything.
This is because a statement that claims no bound where the caller asked for one is a weaker claim, made silently.
`seal --beacon <token>` gives a beacon to `seal` and does not mint one; this is how the tests seal offline.
A caller that names an older block only weakens its own bound.

Read what a beacon does NOT prove.
It does not say that the seal happened AT that time.
A signer can hold a fresh beacon and sign a year later, and nothing here detects that.
A signer can also choose an older block and weaken their own bound, which harms nobody else.
Only backdating becomes impossible.
The timestamp of the block itself is worth even less on its own.
The miner chooses it, and consensus bounds it only loosely.
So `beacon verify` reports the block timestamp as the claim of the miner and treats the HEIGHT as the fact.

A statement whose beacon names a height that does not carry that hash is `valid: false`.
The cause is a reorg or a fabricated bound.
Nobody can tell these two apart from here, and the conclusion is the same in both cases.
If too few explorers answer, or if the explorers disagree, the command throws instead
— that is an outage, not a fact about the statement.
`merkle verify` reports the token that the statement carries, and never a verdict on it.
`merkle verify` makes no network call.
A reader who could not tell a reported bound from a checked bound
would read a green verify as a dated claim.

## Verifying a timestamp

`ots info` only shows the block height that the calendar server reported.
`ots upgrade` puts that height into the file after it checks that it parses.
Neither command checks the height against Bitcoin.
`ots verify` does.
It does not trust the calendar at all:

1. **Queries independent explorers for the block height** (`mempool.space` and `blockstream.info` by default)
   and requires every explorer that answers to agree on the block hash.
   This is the one thing that it trusts a third party for:
   the height → hash mapping.
   If fewer than `--min-sources` explorers answer (default 2), the command refuses and gives no answer.
   With a single responder, there is no cross-check at all.
   That responder would choose both the block hash and the `block_time` that this command reports as the timestamp.
   That timestamp is the one claim that the whole system exists to make.
   To rest on one source on purpose, pass `--min-sources 1`.
2. **Fetches the raw 80-byte block header** and computes two things again, locally.
   The first is the double-SHA256 block hash, which must equal the hash that the explorers agreed on.
   The second is the merkle-root binding:
   the header must commit to the exact value that the operations of the proof replay to.
   Read what that rules out and what it does not rule out:
   it does not check the work behind the header.
   The command reads `bits` from the same header that it examines.
   So "the hash meets its own target" proves nothing.
   Against an attacker who already controls every explorer that answered, a floor at the `powLimit` of mainnet would buy only ~2^32 hashes.
   That is minutes on a GPU.
   A real bound needs the difficulty expected at that height, or a pinned block hash.
   Neither the proof nor the explorer answer carries data to check that against.
   So step 1 is the whole defence:
   independent explorers that agree on the height → hash mapping.
   Step 2 only proves that the header the explorer served is the block that it named.
   (Pinned by the test "check-block-header does not bound the work behind a header".)

```nushell no-run
use nu-multiproof/
# verify the anchor; --file also confirms the proof commits to that content
nu-multiproof ots verify multiproofs/origin-proofs/tree-hashes.CCA016A8/tree-hashes.ots --file multiproofs/origin-proofs/tree-hashes.CCA016A8/tree-hashes.csv
```

Pass `--sources` to cross-check against different explorers.
It replaces the default pair and does not add to it,
so name every explorer to ask.
The command rejects a pending (not-yet-confirmed) proof and points to `ots upgrade`.
