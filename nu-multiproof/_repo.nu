# Resolve a target git repo root. Internal helper shared across the module
# (mod.nu does not re-export _*.nu files).

# Return the given repo path expanded, or — when null — the git root of the
# current directory. Fails fast when neither yields a repo. The old inline
# form (`^git rev-parse --show-toplevel | str trim`) let an empty string flow
# downstream on failure and blew up later with a confusing message.
export def repo-root [repo?: path]: nothing -> path {
    if $repo != null {
        # Why no git check on the explicit path: `merkle verify --repo` accepts
        # a portable proof bundle — a plain directory mirroring the multiproofs/
        # layout (README "Verifying without the origin repo"). Requiring .git
        # here would break that offline-import path.
        return ($repo | path expand)
    }
    let result = ^git rev-parse --show-toplevel | complete
    if $result.exit_code != 0 {
        error make {msg: "not inside a git repository — pass --repo to target one explicitly"}
    }
    $result.stdout | str trim
}
