# SSH signature-file discovery and naming. Both the named form
# `<path>.<signer>.sig` and the bare form `<path>.sig` count as signatures of
# <path> — this module is the one place that knows that grammar, so callers
# can't drift (e.g. clearing only the named form and missing the bare one).

# All signature files for <path>: every `<path>.<signer>.sig` plus the bare
# `<path>.sig` when it exists.
#
# Not `glob $"($path).*.sig"` because: the path is data, but glob reads it as a
# pattern, so `[`, `*` or `?` in a filename made its named sigs invisible —
# this module exists to keep that grammar in one place, and losing sigs is the
# very drift it must prevent. Listing the directory and comparing basenames
# treats every character literally (a variable passed to `ls` is a path, not a
# pattern).
#
# Why --all: sigs of a dotfile are dotfiles too, and plain `ls` hides them —
# `.env.alice.sig` was invisible, so verify reported "no signature files" and
# seal's clearing step left a stale sig behind.
export def sig-files-for [path: path]: nothing -> list<path> {
    let base = $path | path basename
    let dir = $path | path dirname
    let dir = if ($dir | is-empty) { "." } else { $dir }
    # No directory, no signatures — the same answer the previous glob-based
    # discovery gave. Callers clear sigs before the dir is created.
    if not ($dir | path exists) { return [] }
    let entries = ls --all $dir | get name
    let bare_base = $"($base).sig"
    let named = $entries | where {|f|
        let f_base = $f | path basename
        ($f_base | str starts-with $"($base).") and ($f_base | str ends-with ".sig") and $f_base != $bare_base
    }
    $named ++ ($entries | where {|f| ($f | path basename) == $bare_base })
}

# Signer label carried by a sig filename, given the file it signs.
# Bare `<file>.sig` -> null; named `<file>.<signer>.sig` -> <signer>.
# Needs the signed file to disambiguate: `a.b.sig` is bare-for-`a.b`, not
# named-"b"-for-`a`, and only the base tells them apart.
export def signer-from-sig [file: path sig_path: path]: nothing -> any {
    let base = $file | path basename
    let sig_base = $sig_path | path basename
    if $sig_base == $"($base).sig" {
        null
    } else {
        $sig_base | str replace $"($base)." "" | str replace --regex '\.sig$' ''
    }
}
