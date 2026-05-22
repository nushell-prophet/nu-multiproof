# Internal helpers for ots.nu. Not part of the public nu-multiproof API
# (mod.nu does not re-export this file). Lives separately so the pure
# extensionless-input case can be tested without invoking `stamp` and the
# calendar network call.

# Bundle copy-path for an input file. Pure; extracted from `stamp`.
# Why no trailing dot: extensionless input ("README") was producing "README."
# because `($stem).($ext)` collapsed to "README." when `$ext` was empty.
export def copy-path-for [file: path, bundle_dir: path]: nothing -> string {
    let parsed = $file | path parse
    if ($parsed.extension | is-empty) {
        $"($bundle_dir)/($parsed.stem)"
    } else {
        $"($bundle_dir)/($parsed.stem).($parsed.extension)"
    }
}
