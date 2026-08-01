# Directory listing where the directory is data, not a pattern.
#
# Why not `glob ($dir | path join "*.pub")`: the pattern is built by
# interpolation, so any `[`, `*`, `?` or `{` in $dir — a repo checked out to
# `/src/re[po]/` is enough — is read as pattern syntax and the call returns an
# empty list. Every failure of that shape is silent: zero loose objects copied
# into a proof bundle, a duplicate key not detected at registration, a pending
# OTS stamp never upgraded. `ls` takes a variable argument as a literal path,
# so listing and filtering by name keeps the path as data.

# Files (anything that is not a directory, symlinks included) directly in
# $dir, or under it with --recursive. Absent directory -> []. Names are
# compared literally, never as patterns.
#
# --regular narrows that to `type == file`, dropping symlinks. Nushell types a
# symlink as `symlink` whatever it points at, so without this a link to a
# directory — or a dangling one — comes back in the list and throws at the first
# `open`. A caller that reads the bytes and treats them as the named file's own
# wants this: the same reason `_sig.nu` refuses a symlinked signature, since the
# bytes behind a link are not the ones the name describes.
export def list-files [
    dir: path
    --recursive # walk subdirectories too
    --suffix: string = "" # keep only names ending with this
    --regular # keep only regular files, dropping symlinks
]: nothing -> list<path> {
    if not ($dir | path exists) { return [] }
    let entries = ls --all $dir
    let here = $entries
        | where {|e| if $regular { $e.type == "file" } else { $e.type != "dir" } }
        | get name
        | where {|f| $suffix == "" or ($f | path basename | str ends-with $suffix) }
    if not $recursive {
        return $here
    }
    let deeper = $entries
        | where type == dir
        | get name
        | each {|sub| list-files $sub --recursive --suffix $suffix --regular=$regular }
        | flatten
    $here ++ $deeper
}

# Subdirectories directly in $dir. Absent directory -> [].
export def list-dirs [dir: path]: nothing -> list<path> {
    if not ($dir | path exists) { return [] }
    ls --all $dir | where type == dir | get name
}
