# Which commit the manifest describes — written only when it can be checked.
#
# The manifest is built from the working tree, not from HEAD (see tree-hashes.nu),
# so a commit hash written beside it is not automatically true. It becomes true
# under one condition: multiproofs/ is excluded from the manifest, so the manifest
# of HEAD's tree and the manifest of a clean working tree are byte-identical.
# Then anyone can check out that commit, rebuild, and compare the merkle root.
#
# Hence the rule this module implements: a dirty tree gets no record at all.
# Not a `dirty` marker beside the hash — that record could never be checked by
# anyone, and it would sit inside a directory whose contents are checkable by
# definition. It would also be wrong in a specific way: sealing a dirty tree and
# then committing makes the sealed state the tree of the NEXT commit, so the
# honest answer at seal time is a hash that does not exist yet, and naming the
# stale parent instead states a falsehood precisely. The unverifiable pointer
# keeps its home in the seal commit body, which is a human channel.
#
# The bound worth knowing: the manifest is a function of the CHECKOUT, not of the
# commit. Checkout filters (core.autocrlf, .gitattributes, git-LFS) are machine
# configuration and not carried by the commit, so two checkouts of one commit can
# hash differently. That fails safe — a verifier says "does not match", never
# "matches" — so it is stated here rather than guarded.
#
# Internal module: mod.nu does not re-export _*.nu files.

use _layout.nu [ MULTIPROOFS_DIR snapshot-path ]

export const SNAPSHOT_SCHEMA = "multiproof-snapshot-v1"

# One-line record: "multiproof-snapshot-v1 <40 or 64 lowercase hex>" + exactly one
# trailing "\n". Statement form, same reason as the merkle root statement: a bare
# hash says nothing about what it is a hash OF.
export def snapshot-statement [commit: string]: nothing -> string {
    $"($SNAPSHOT_SCHEMA) ($commit)\n"
}

# Read the commit back out of a record file.
#
# Both git object formats are accepted by hex length — 40 for sha1, 64 for
# sha256. No format token is stored: the commit is HEAD of the repo at hand, so
# the format is whatever that repo runs and the length says which. (The manifest
# went the other way — it names both formats in two columns — because a lookup
# key is used against repos other than the one it was written in.)
#
# The schema token is captured and compared, never spelled into the regex — the
# lesson from parse-root-statement, where hardcoding it let the parser keep
# accepting an old schema the writer had already stopped writing.
export def parse-snapshot-statement [file: path]: nothing -> string {
    let content = open --raw $file | into string
    let matched = $content | parse --regex '\A(?<schema>\S+) (?<commit>[0-9a-f]{40}|[0-9a-f]{64})\n\z'
    if ($matched | is-empty) or $matched.schema.0 != $SNAPSHOT_SCHEMA {
        error make {msg: $"malformed snapshot record ($file): expected '($SNAPSHOT_SCHEMA) <40 or 64 lowercase hex>' with exactly one trailing newline"}
    }
    $matched.commit.0
}

# HEAD, and whether the tree the manifest covers still equals it.
#
# Returns null when there is no HEAD to name: a repo before its first commit, or
# a --repo pointing at a plain directory (repo-root accepts one — a portable
# bundle is not a git repo). Not an error: nothing is wrong, there is simply
# nothing to record.
#
# The status invocation, flag by flag:
#   --untracked-files=no  untracked files never enter the manifest (git ls-files
#                         reads the index), so they cannot falsify the record.
#                         Without this, multiproofs/ itself reads as `?? ` before
#                         the first seal is committed.
#   -- .                  --repo is NOT required to be a git root: repo-root takes
#                         an explicit path verbatim, and nu-cybergraph passes a
#                         subdirectory. `git ls-files` lists under the cwd, so the
#                         manifest covers that subtree — but `git status` reports
#                         the whole repository. Without this pathspec, unrelated
#                         work elsewhere in the repo would suppress the record for
#                         a change that cannot affect the manifest.
#   :(exclude)multiproofs the proof directory is rewritten by every seal, and it
#                         is outside the manifest, so its state says nothing about
#                         whether the manifest matches the commit.
#   --no-optional-locks   `status` writes refreshed stat data back through the
#                         index lock. A library inspecting someone else's repo
#                         should not take it.
#
# Not `diff-index --quiet HEAD`: it reports stale stat info as a difference
# unless the index is refreshed first, which `status` does as part of its job.
export def snapshot-state [root: path]: nothing -> any {
    let head = do { ^git -C $root rev-parse HEAD } | complete
    if $head.exit_code != 0 { return null }

    let exclude_spec = ":(exclude)" + $MULTIPROOFS_DIR
    let status = do {
        ^git --no-optional-locks -C $root status --porcelain --untracked-files=no -- "." $exclude_spec
    } | complete
    # Not a third state — the same "nothing to record". And not removable: a
    # failed `status` returns empty stdout through `complete`, which the line
    # below would read as a clean tree and record a commit for a tree nobody
    # checked. Silence is the safe direction, since absence already means "no
    # claim"; a hard throw here would fail the manifest build over a note beside
    # it.
    if $status.exit_code != 0 { return null }

    {commit: ($head.stdout | str trim) clean: ($status.stdout | str trim | is-empty)}
}

# Write the record for this manifest, or make sure none is left behind.
#
# The delete is the load-bearing half: a record written by an earlier clean seal
# would otherwise survive beside a manifest built from a dirty tree, claiming a
# commit that manifest no longer describes. Deleting the stale artifact is the
# fix; filtering it out at read time would not be.
#
# Returns the commit it recorded, or null when it recorded nothing. The commit is
# read back out of the file rather than returned from memory — this module writes
# an artifact, so it parses that artifact back before reporting success.
export def write-snapshot [root: path]: nothing -> any {
    let path = snapshot-path $root
    let state = snapshot-state $root

    if $state == null or (not $state.clean) {
        rm --force $path
        return null
    }

    snapshot-statement $state.commit | save --raw --force $path
    parse-snapshot-statement $path
}
