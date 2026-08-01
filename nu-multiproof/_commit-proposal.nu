use _layout.nu MULTIPROOFS_DIR

# The `git commit` command a freshly sealed repo should be committed with,
# written for a human to read and edit before running it.
#
# Why a proposal and not a commit: `seal` deliberately stops short of committing
# (see seal.nu) — the decision is the user's, with context the pipeline does not
# have: message, scope, timing. What was missing is not the decision but the
# wording. A seal committed under "wip", or spread over three commits, makes the
# log useless for the one question it should answer: when was this root sealed.
# So this standardizes the wording and leaves the decision where it was.
#
# Why it is a multi-line block with variables rather than one long line: the
# whole point is that the user reads and edits the message before running it,
# and a body escaped into `\n` inside a quoted argument is the one shape that
# cannot be edited comfortably. `$msg` gives the body real lines; `$repo` is
# used twice. The cost is nothing — Nushell throws on a non-zero external exit,
# so a failed `add` still stops before `commit`, exactly as `;` did.

# Quote a value for the Nushell block the caller is handed.
#
# Why escape at all: the block is pasted into a prompt ready to run, and a repo
# path is not this module's to trust — it may hold a quote or a backslash.
#
# Why `to nuon` and not a hand-written escaper: nuon IS Nushell's own string
# literal syntax, so its serializer already owns the job of staying in step with
# the parser. The escaper this replaced covered `\` and `"`, which is all that
# is needed today — and that is exactly the kind of "all that is needed today"
# that rots silently when the parser gains a rule.
#
# What it does NOT do is sanitize for display: a control character in the value
# reaches the prompt raw, so a repo path carrying ANSI escapes could repaint the
# line the user is meant to read before pressing enter. Left as is deliberately
# (the user's call) — the repo root is a path you chose, not attacker-supplied
# input. The guarantee here is that the block PARSES as one command with one
# argument, never that it renders honestly.
#
# Real newlines become the two characters `\n` unless --multiline: a path that
# spans lines is still safely inside the quotes, but it would silently change
# how many lines the proposal occupies. The message body is the one place a
# newline is meant, and there it stays a newline.
export def quote-arg [s: string --multiline]: nothing -> string {
    let quoted = $s | to nuon

    if $multiline { $quoted } else { $quoted | str replace --all "\n" '\n' }
}

# Build the block from what `seal` returned.
#
# `signer` is passed in rather than read off the signature's filename: a
# principal is a key's fingerprint, derived from key material, and `seal`
# already resolved it from the signing key before step 3. Reading it back out of
# `<file>.<fingerprint>.sig` is exactly the filename-as-identity shape this repo
# removed — the same key rendered as two signers depending on which file name
# was to hand.
export def seal-commit-line [
    result: record # what `seal` returned
    root: path # repo root the seal targeted
    signer: string # principal, resolved from key material
]: nothing -> string {
    let stamped = ($result | get --optional root_ots) != null

    let subject = $"seal: multiproofs/ describes the tree at merkle root ($result.merkle_root | str substring 0..<8)"

    let bundle_line = if $stamped {
        [$"Bundle: ($result.root_ots | path dirname | path relative-to $root)"]
    } else {
        []
    }

    # Why "pending" is stated rather than read: a proof is pending by
    # construction the moment the calendar accepts it — a Bitcoin anchor is
    # hours to days away — so this claims nothing the seal did not just do.
    let anchor_line = if $stamped {
        let endorsements = $result | get --optional sig_ots | default [] | length
        let plural = if $endorsements == 1 { "endorsement" } else { "endorsements" }
        $"Anchors: content + ($endorsements) ($plural), pending until Bitcoin confirms"
    } else {
        "Anchors: none, sealed with --no-stamp"
    }

    let message = [
        $subject
        ""
        $"Root CID: ($result.root_cid)"
        $"Merkle root: ($result.merkle_root)"
        $"Signed by: ($signer)"
        ...$bundle_line
        $anchor_line
    ] | str join "\n"

    # Why `git -C $repo`: the sealed repo need not be the shell's. `seal --repo`
    # can target another one, and even for the local repo a bare pathspec
    # resolves against the CWD, so it fails whenever the prompt sits in a
    # subdirectory.
    #
    # Why the whole directory and not the paths in $result: seal both writes
    # and DELETES inside it — a signature over bytes regen changed is cleared —
    # and a deletion appears in no result field. A proposal naming only written
    # files would commit a folder git still holds a cleared signature for. It is
    # the directory seal owns end to end, which is what makes the wholesale add
    # exact here rather than an `add -A` in disguise. `--` because the pathspec
    # is data.
    [
        $"let repo = (quote-arg $root)"
        $"let msg = (quote-arg $message --multiline)"
        ""
        $"git -C $repo add -- ($MULTIPROOFS_DIR)"
        "git -C $repo commit -m $msg"
    ] | str join "\n"
}
