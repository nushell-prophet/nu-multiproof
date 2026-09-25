use std/assert
use std/testing *

use ../nu-multiproof/_commit-proposal.nu [ seal-commit-line quote-arg ]
use _fixtures.nu [ setup cleanup ]

# Only the snapshot tests below need a repo on disk; the rest pin wording against
# a hand-built record and pass a path that never exists — which is also what
# keeps the line count in "the message body is real lines" at 11, since a path
# that is not a git repo names no commit.

# A repo with one commit. Returns its root and that commit.
def committed-repo [tmp_dir: path]: nothing -> record {
    let repo = $tmp_dir | path join repo
    mkdir $repo
    ^git -C $repo init -q
    "alpha\n" | save --force ($repo | path join a.txt)
    ^git -C $repo add -- . o+e>| ignore
    ^git -C $repo -c user.email=t@t -c user.name=t commit -q -m init
    {root: $repo commit: (^git -C $repo rev-parse HEAD | str trim)}
}

# What a stamped seal returns, with the fields the proposal reads. Hand-built
# rather than produced by `seal`: the point is to pin the wording against a
# known input, and a round-trip through the builder would only prove the
# proposal agrees with whatever seal happens to return today.
def stamped-result []: nothing -> record {
    {
        manifest: "/repo/multiproofs/tree-hashes.csv"
        root_cid: "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        merkle_root: "ee947cd6a1f3b2c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081920a3b4c"
        root_sig: "/repo/multiproofs/tree-root.txt.abc.sig"
        bundle: "/repo/multiproofs/ots-timestamps/tree-root.EE947CD6"
        root_ots: "/repo/multiproofs/ots-timestamps/tree-root.EE947CD6/tree-root.ots"
        sig_ots: ["/repo/multiproofs/ots-timestamps/tree-root.EE947CD6/tree-root.txt.abc.ots"]
    }
}

@test
def "the subject carries the first 8 hex of the merkle root" [] {
    let line = seal-commit-line (stamped-result) "/repo" "abc123"

    # The trailing newline is part of the match on purpose: it is what pins the
    # truncation. The full root is in the body, so a plain `str contains` of the
    # 8 characters would pass even if the subject carried all 64 — and 64 hex
    # characters push everything else off a `git log --oneline` line.
    assert str contains $line $'let msg = "seal: multiproofs/ describes the tree at merkle root ee947cd6(char newline)'
}

@test
def "a stamped seal names its bundle and reports both anchors pending" [] {
    let line = seal-commit-line (stamped-result) "/repo" "abc123"

    assert str contains $line "Bundle: multiproofs/ots-timestamps/tree-root.EE947CD6"
    assert str contains $line "Anchors: content + 1 endorsement, pending until Bitcoin confirms"
}

@test
def "two signatures are counted, and read as plural" [] {
    let two = stamped-result | update sig_ots {|r| $r.sig_ots | append "/repo/x.ots" }

    let line = seal-commit-line $two "/repo" "abc123"

    assert str contains $line "content + 2 endorsements"
}

@test
def "a seal with no stamp reports no anchor and names no bundle" [] {
    let line = seal-commit-line (stamped-result | reject bundle root_ots sig_ots) "/repo" "abc123"

    assert str contains $line "Anchors: none, sealed with --no-stamp"
    # A bundle line here would name a directory the seal never wrote.
    assert not ($line | str contains "Bundle:")
}

# --no-content-anchor: a bundle was written and digests did reach the calendar,
# so "none, sealed with --no-stamp" would be the opposite of what happened. The
# line has to name what was anchored and leave out what was not.
@test
def "a seal that anchored only its signatures says so and still names its bundle" [] {
    let line = seal-commit-line (stamped-result | reject root_ots) "/repo" "abc123"

    assert str contains $line "Anchors: 1 endorsement, pending until Bitcoin confirms"
    assert not ($line | str contains "content +")
    assert str contains $line "Bundle: multiproofs/ots-timestamps/tree-root.EE947CD6"
}

@test
def "the signer is the principal passed in, not anything read off a filename" [] {
    let fpr = "ed2386359d82cbeba2214f993392a15db8c99627173532f32f01934957799dc2"

    # The result's own .sig paths say "abc" — the proposal must ignore them.
    let line = seal-commit-line (stamped-result) "/repo" $fpr

    assert str contains $line $"Signed by: ($fpr)"
    assert not ($line | str contains "Signed by: abc")
}

@test
def "git is aimed at the sealed repo rather than the current directory" [] {
    # `seal --repo` can target another repo, and even for the local one the
    # pathspec `multiproofs` resolves against the CWD — so a proposal without
    # -C fails from any subdirectory.
    let elsewhere = stamped-result
        | update bundle {|r| $r.bundle | str replace "/repo/" "/elsewhere/repo/" }

    let line = seal-commit-line $elsewhere "/elsewhere/repo" "abc123"

    assert str contains $line 'let repo = "/elsewhere/repo"'
    assert str contains $line "git -C $repo add -- multiproofs"
    assert str contains $line "git -C $repo commit -m $msg"
    # The bundle stays repo-relative, so the line reads the same wherever the
    # repo sits on disk.
    assert str contains $line "Bundle: multiproofs/ots-timestamps/tree-root.EE947CD6"
}

@test
def "the message body is real lines, not escapes" [] {
    let line = seal-commit-line (stamped-result) "/repo" "abc123"

    # The user is meant to edit this before running it, and a body escaped into
    # `\n` inside a quoted argument is the one shape that cannot be edited
    # comfortably. So the escape must NOT be there.
    assert not ($line | str contains '\nMerkle root: ')
    assert str contains $line "\nMerkle root: "
    # Subject, blank line, four body lines, blank line, two git lines.
    assert equal ($line | lines | length) 11
}

@test
def "a clean tree names the commit the seal was taken from" [] {
    let repo = committed-repo $in.tmp_dir

    # No bundle: its path in the fixture sits under /repo, and the proposal
    # renders it relative to the root — which is a temp repo here.
    let line = seal-commit-line (stamped-result | reject bundle root_ots sig_ots) $repo.root "abc123"

    # The trailing newline is part of the match: without it this would also pass
    # for the uncommitted-changes wording, which is the one thing it must tell
    # apart.
    assert str contains $line $"Snapshot of: ($repo.commit)\n"
}

@test
def "an uncommitted change is stated here, the one channel that may carry it" [] {
    let repo = committed-repo $in.tmp_dir
    "edited\n" | save --force ($repo.root | path join a.txt)

    let line = seal-commit-line (stamped-result | reject bundle root_ots sig_ots) $repo.root "abc123"

    # multiproofs/snapshot.txt is not written at all for a dirty tree, because
    # nobody could check it. A commit body is read by people, so it can say the
    # sealed tree was this commit plus work in progress — and it must, or the
    # bare hash would read as a claim the file deliberately refuses to make.
    assert str contains $line $"Snapshot of: ($repo.commit) plus uncommitted changes"
}

@test
def "a repo path holding a quote still parses as one command" [] {
    # Hostile input, not a round-trip: a path is data, and this string is handed
    # to the user's prompt ready to run. Nothing in this repo produces such a
    # path — that is the point of building it by hand.
    let nasty = '/tmp/we"ird\path'

    let quoted = quote-arg $nasty

    # Parsed back by Nushell itself rather than compared to an expected
    # spelling: what matters is that the parser returns the original bytes.
    let round_tripped = ^nu --commands $"print --raw ($quoted)" | str trim --right --char "\n"
    assert equal $round_tripped $nasty
}

@test
def "multiline mode keeps newlines but still escapes a quote" [] {
    # The message body is the one place a newline is meant. A quote in it would
    # still end the string early, so only the newline rule relaxes.
    let body = "line one\nhe said \"hi\"\nline three"

    let quoted = quote-arg $body --multiline

    assert equal ($quoted | lines | length) 3
    let round_tripped = ^nu --commands $"print --raw ($quoted)" | str trim --right --char "\n"
    assert equal $round_tripped $body
}

@test
def "a newline in a path cannot break out of the quoted argument" [] {
    let nasty = "/tmp/a\nrm -rf /"

    let quoted = quote-arg $nasty

    assert equal ($quoted | lines | length) 1
    let round_tripped = ^nu --commands $"print --raw ($quoted)" | str trim --right --char "\n"
    assert equal $round_tripped $nasty
}
