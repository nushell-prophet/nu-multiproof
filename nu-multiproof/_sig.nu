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
    # Why `type == file` and not just a name match: `seal` passes this list
    # straight to `rm`. A directory named `tree-hashes.csv.bundle.sig` was
    # deleted silently when empty, and made `rm` throw when not — aborting seal
    # after the manifest was regenerated and before signing, leaving an unsigned
    # catalogue. A signature is a regular file; a symlink is not one either
    # (`verify` would read through it to bytes the name does not describe).
    let entries = ls --all $dir | where type == file | get name
    let bare_base = $"($base).sig"
    let named = $entries | where {|f|
            let f_base = $f | path basename
            let named_form = ($f_base | str starts-with $"($base).") and ($f_base | str ends-with ".sig") and $f_base != $bare_base
            # ...unless the name also reads as some *other* file's bare signature,
            # and that file is on disk. `tree-hashes.csv.gz.sig` beside an existing
            # `tree-hashes.csv.gz` is the archive's signature, not a "gz"-named
            # signature of `tree-hashes.csv` — and `seal` deleted it as stale while
            # the file it signs sat untouched. `original-for-sig` below already
            # settles this ambiguity by asking the filesystem, bare reading first;
            # discovery asks the same question so the two cannot drift.
            #
            # The other way round is fail-closed: plant an empty `<file>.<signer>`
            # and that signer's sig drops out of discovery, so verify says "no
            # signature files found" instead of destroying one.
            $named_form and not (($f | str replace --regex '\.sig$' '') | path exists)
        }
    $named ++ ($entries | where ($it | path basename) == $bare_base)
}

# Name of the signature file for <path>: bare when no signer is named.
export def sig-path-for [path: path signer?: string]: nothing -> path {
    if $signer == null { $"($path).sig" } else { $"($path).($signer).sig" }
}

# The file a `.sig` covers, given only the signature's name.
#
# The two forms are ambiguous on their own: `doc.txt.sig` is the bare sig of
# `doc.txt` and also the "txt"-named sig of `doc`. Only the filesystem can say
# which, so both candidates are tried, bare first.
export def original-for-sig [sig_path: path]: nothing -> path {
    if not ($sig_path | str ends-with ".sig") {
        error make {msg: $"not a signature file name: ($sig_path)"}
    }
    let bare = $sig_path | str replace --regex '\.sig$' ''
    if ($bare | path exists) { return $bare }
    let named = $bare | str replace --regex '\.[^./]+$' ''
    if $named == $bare or not ($named | path exists) {
        error make {msg: $"cannot find the file ($sig_path) signs — tried ($bare) and ($named)"}
    }
    $named
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
