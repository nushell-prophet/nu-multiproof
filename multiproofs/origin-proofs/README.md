# Origin proofs

This directory is **archival, not operational**. It preserves proofs of how
this repository came to exist; it is not part of the live OTS workflow.

Operational timestamps go to [`../ots-timestamps/`](../ots-timestamps/).

## What's here

- `tree-hashes.CCA016A8/` — OpenTimestamps proof that the `nu-multiproof/*`
  subtree, as of source commit `ff8545e`, was timestamped on Bitcoin block
  939896. The manifest covers the full source repo (59 entries); the 24 rows
  under `nu-multiproof/` and `multiproofs/` are the subtree that was
  extracted. SSH-signed by `maxim-uvarov2`.

- `tree-hashes.93223B2F/` — bridge stamp. First OTS made from inside this
  standalone repo after extraction, confirmed on Bitcoin block 940583.
  Connects the cross-repo extraction proof above to this repo's ongoing
  operational timestamps in `../ots-timestamps/`.

A third bundle used to sit here: `git-proof/`, a merkle proof that source
commit `ff8545e` was signed with an ECDSA-SK hardware key and contained the 7
`nu-multiproof/*` files that seeded this repo. It was removed together with the
`git-proof` command, the only thing that could check it. Both are in this
repo's git history if the claim is ever needed again.

## Why these are kept separate from ots-timestamps/

These bundles are irreplaceable: the source repo does not need to exist for
someone to verify them. They are also distinct in scope — operational stamps
cover only files currently tracked in this repo, while the extraction proof
covers a snapshot of the larger source repo.
