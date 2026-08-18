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
    let here = (if $regular { $entries | where type == file } else { $entries | where type != dir })
        | get name
        | where $suffix == "" or ($it | path basename | str ends-with $suffix)
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

# Copy a file so that a failure cannot pass for success.
#
# Why not `cp`: it prints the reason on stderr and exits 0. Measured on nushell
# 0.114.1, and the source says why — `ucp.rs:294` matches
# `CpError::NotAllFilesCopied` and drops it, under its own TODO saying the exit
# code should be an error as GNU cp's is. Every per-file failure folds into that
# one variant: no space left, a read-only mount, an I/O error, an unreadable
# source. In this repo that meant `ots stamp` reporting a frozen copy and
# exiting 0 for a file that was not on disk — a bundle whose proofs commit to
# bytes it does not hold. `open` and `save` both raise.
#
# Why the bytes are collected rather than streamed into `save`: src and dest can
# be the same bytes under two names — a hard link, or one path reached twice on
# a case-insensitive filesystem. Streaming truncates the destination while the
# source is still being read from it, and nushell's own same-file check is by
# path, so it does not catch an alias (measured: both names left at 0 bytes, no
# error). Collected, the read has finished before the write starts.
export def copy-file [
    src: path
    dest: path
    --force # overwrite an existing destination, as `cp` did unconditionally
]: nothing -> nothing {
    let bytes = open --raw $src | into binary
    $bytes | save --raw --force=$force $dest
}

# Subdirectories directly in $dir. Absent directory -> [].
export def list-dirs [dir: path]: nothing -> list<path> {
    if not ($dir | path exists) { return [] }
    ls --all $dir | where type == dir | get name
}

# A path as the caller would type it from where they stand: relative to the
# current directory when it sits under it, absolute when it does not.
#
# For a path this toolchain constructs and hands back for a person to read.
# A caller who needs a handle rather than a label takes `| path expand` — the
# exact inverse, since the value is relative to the cwd it was made in.
#
# Why the cwd and not the repo root: the absolute form spent most of the row
# on a prefix the reader is already standing in, and relative to the cwd the
# value still pastes straight into `open`.
#
# Why a prefix test and not `try { path relative-to } catch { }`: "not under
# here" is an ordinary answer, not a failure, and burying it in a catch hides
# that. Not an anchored regex either — the cwd is data, so a directory named
# `test (2)` would be read as pattern syntax. The trailing separator is part
# of the prefix: without it `/a/bc` counts as under `/a/b`.
export def cwd-relative []: path -> path {
    let p = $in
    if ($p | str starts-with ($env.PWD | path join "")) {
        $p | path relative-to $env.PWD
    } else {
        $p
    }
}
