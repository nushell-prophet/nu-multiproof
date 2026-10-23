# Resolve a target git repo root. Internal helper shared across the module
# (mod.nu does not re-export _*.nu files).

use _layout.nu MULTIPROOFS_DIR

# Return the given repo path expanded, or — when null — the nearest directory
# from the current one up to the git root that holds multiproofs/; with none,
# the git root itself. Under --init, the current directory. Fails fast when
# not inside a git repo. The old inline form (`^git rev-parse --show-toplevel |
# str trim`) let an empty string flow downstream on failure and blew up later
# with a confusing message.
export def repo-root [
    repo?: path
    --init # Resolve to the current directory, without looking for multiproofs/
]: nothing -> path {
    if $repo != null {
        # Why no git check on the explicit path: `merkle verify --repo` accepts
        # a portable proof bundle — a plain directory mirroring the multiproofs/
        # layout (README "Verifying without the origin repo"). Requiring .git
        # here would break that offline-import path. Existence IS checked:
        # unchecked, a typo surfaces later as a confusing downstream error.
        let expanded = $repo | path expand

        if not ($expanded | path exists) {
            error make {msg: $"repo path does not exist: ($expanded)"}
        }
        return $expanded
    }
    nearest-home $MULTIPROOFS_DIR --init=$init
}

# The deepest directory between the current one and the git root that holds
# `marker`; with none, the git root. Under --init, the current directory.
#
# Why the nearest marker and not the git root: one git repo can hold several
# homes — a monorepo carries each project it imports in a subdirectory, each
# with its own multiproofs/ — and the git root then names the wrong one, or
# none. Stopping at the git root keeps a home outside the repo out of reach.
#
# Why the candidates are built from --show-prefix and not by walking up
# `$env.PWD`: a cwd reached through a symlink names the same directory with
# another string than --show-toplevel, so an up-walk comparing the two never
# meets the git root and climbs out to `/`. git states both in one spelling.
export def nearest-home [marker: string --init]: nothing -> path {
    let result = ^git rev-parse --show-toplevel --show-prefix | complete

    if $result.exit_code != 0 {
        error make {msg: "not inside a git repository" help: "pass --repo to target one explicitly"}
    }
    let lines = $result.stdout | lines
    let toplevel = $lines.0
    let parts = $lines | get --optional 1 | default "" | path split
    let candidates = 0..($parts | length) | each {|n| $toplevel | path join ...($parts | first $n) } | reverse

    # Why init takes no part in the walk: a home above would always win, and in
    # a monorepo whose root holds one, `init` in a new project would register
    # the key into the root's trust list instead of starting a new home.
    #
    # Why refused inside the marker: there cwd is part of a home, and a new
    # home there would sit inside the old one, a stray `seal` refuses.
    if $init {
        let inside = $parts | enumerate | where item == $marker | get --optional 0.index

        if $inside != null {
            let home = $toplevel | path join ...($parts | first $inside)

            error make {msg: $"the current directory is inside ($marker)/ of ($home)" help: $"run init from ($home), or pass --repo"}
        }
        return ($candidates | first)
    }
    let found = $candidates | where {|dir| ($dir | path join $marker | path type) == dir }

    $found | get --optional 0 | default $toplevel
}
