# Filesystem layout of the multiproofs/ output tree. One source of truth for
# every path the module reads or writes under a target repo root — so a layout
# change is one edit here, not six files silently disagreeing.

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
