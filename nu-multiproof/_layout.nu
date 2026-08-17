# Filesystem layout of the multiproofs/ output tree: the directories and the two
# top-level artifact names, in one place, so a layout change is one edit here
# rather than six files silently disagreeing.
#
# Not everything under multiproofs/ is here yet. The OTS bundle grammar
# (<stem>.<HASH8>/<stem>.ots) is built inline in ots.nu and its `<stem>.`
# prefix re-derived in merkle.nu; `.pub`, `.sig` and `.multiproof.json` are
# spelled at their use sites.
# Anything moved in here should come with its readers.

export const MULTIPROOFS_DIR = "multiproofs"
export const PUBKEYS_DIR = "pubkeys"
export const OTS_DIR = "ots-timestamps"
export const MANIFEST_FILE = "tree-hashes.csv"
# Not tree-hashes.root because: ots stamp keys bundle dirs by file stem, so a
# root file sharing the CSV's stem would collide with the manifest's bundles.
# Why .txt: the statement is one ASCII line meant for human eyes and exact-byte
# signing — .txt renders as text everywhere; a structured format (.json/.nuon)
# has no canonical byte form, and a custom extension is opaque for no gain.
export const MERKLE_ROOT_FILE = "tree-root.txt"
export const INCLUSION_PROOFS_DIR = "inclusion-proofs"
# Why .txt and one line: same argument as MERKLE_ROOT_FILE above — a statement
# for human eyes with an exact byte form. This one is not signed (see
# _snapshot.nu), so it carries no schema-versioned signing target, only its own
# name.
export const SNAPSHOT_FILE = "snapshot.txt"

# <root>/multiproofs
export def multiproofs-dir [root: path]: nothing -> path {
    $root | path join $MULTIPROOFS_DIR
}

# <root>/multiproofs/pubkeys
export def pubkeys-dir [root: path]: nothing -> path {
    $root | path join $MULTIPROOFS_DIR $PUBKEYS_DIR
}

# <root>/multiproofs/ots-timestamps
export def ots-dir [root: path]: nothing -> path {
    $root | path join $MULTIPROOFS_DIR $OTS_DIR
}

# <root>/multiproofs/tree-hashes.csv
export def manifest-path [root: path]: nothing -> path {
    $root | path join $MULTIPROOFS_DIR $MANIFEST_FILE
}

# <root>/multiproofs/tree-root.txt
export def merkle-root-path [root: path]: nothing -> path {
    $root | path join $MULTIPROOFS_DIR $MERKLE_ROOT_FILE
}

# <root>/multiproofs/inclusion-proofs
export def inclusion-proofs-dir [root: path]: nothing -> path {
    $root | path join $MULTIPROOFS_DIR $INCLUSION_PROOFS_DIR
}

# <root>/multiproofs/snapshot.txt
export def snapshot-path [root: path]: nothing -> path {
    $root | path join $MULTIPROOFS_DIR $SNAPSHOT_FILE
}
