# SSH signature-file discovery and naming. Both the named form
# `<path>.<signer>.sig` and the bare form `<path>.sig` count as signatures of
# <path> — this module is the one place that knows that grammar, so callers
# can't drift (e.g. clearing only the named form and missing the bare one).

# All signature files for <path>: every `<path>.<signer>.sig` plus the bare
# `<path>.sig` when it exists.
export def sig-files-for [path: path]: nothing -> list<path> {
    let named = glob $"($path).*.sig"
    let bare = $"($path).sig"
    if ($bare | path exists) { $named ++ [$bare] } else { $named }
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
