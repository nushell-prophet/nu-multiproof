# Filesystem layout of the multiproofs/ output tree. One source of truth for
# every path the module reads or writes under a target repo root — so a layout
# change is one edit here, not six files silently disagreeing.

export const MULTIPROOFS_DIR = "multiproofs"
export const PUBKEYS_DIR = "pubkeys"
export const OTS_DIR = "ots-timestamps"
export const MANIFEST_FILE = "tree-hashes.csv"

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
