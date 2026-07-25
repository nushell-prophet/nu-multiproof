# Render an OpenSSH allowed_signers body from every *.pub in a directory.
# Shared by ssh-sign verify (named principals so find-principals returns the
# signer) and git-proof (wildcard principal for collective commit-signing trust).

use _fs.nu list-files
use _pubkey-helpers.nu canonical-file

# Characters a principal may not hold. The file's syntax is whitespace-
# separated with a comma-separated principal list, and principals are matched
# as patterns — so each of these writes a *different* line than the one
# intended: a stem with a newline injected a whole extra entry, a stem with a
# space or comma claimed two principals, and a file named `*.pub` would have
# trusted its key for every signer. Reject, never normalize: the file name is
# the operator's to fix.
#
# `/` is here for the other half of the grammar: a filename stem can never
# hold one, but `ssh-sign sign --name` reaches the same rule and its value is
# interpolated into `<file>.<name>.sig`, so a slash writes the signature into
# another directory where discovery never finds it again.
const FORBIDDEN_IN_PRINCIPAL = '["#,\\*?!/\s]|\p{Cc}'

# One line per pubkey: `<principal> namespaces="<namespace>" <key>`.
# --wildcard uses "*" for every key (a collective trust statement); otherwise
# each key's filename stem is its principal.
#
# Why every key goes through `pubkey canonical` rather than being copied
# through: a key file holding two lines emitted a principal-less second line.
# ssh-keygen does not reject the file over it — it writes "<file>:1: invalid
# key" to stderr, skips that line and carries on (measured on OpenSSH 10.2p1;
# pinned by tests/test_allowed-signers.nu "ssh-keygen skips a malformed entry
# rather than failing"). Skipping is the worse outcome: the rendered trust
# list no longer says what pubkeys/ says, the warning is swallowed by the
# `complete` wrapped around every ssh-keygen call here, and the signer whose
# key is broken comes back as an unrecognized signer with nothing pointing at
# the cause. A broken trust list is an error, raised at the file that broke it.
export def allowed-signers-body [
    pubkeys_dir: path
    --namespace: string = "file"
    --wildcard # use "*" as the principal for every key instead of its stem
]: nothing -> string {
    # Why a `for` and not an `each`: an `error make` raised inside a closure
    # reaches the caller as "Eval block failed with pipeline input", with the
    # message naming the broken file buried in `$e.inner`. The operator has to
    # be told which file to fix.
    mut lines = []
    for file in (list-files $pubkeys_dir --suffix ".pub") {
        # Name before content: a name this file cannot express is the operator's
        # to fix, and saying so beats whatever `open` reports about it.
        let principal = if $wildcard { "*" } else { principal-for $file }
        let key = canonical-file $file | str trim
        $lines = ($lines | append $"($principal) namespaces=\"($namespace)\" ($key)")
    }
    $lines | str join "\n"
}

# The principal a pubkey file claims: its filename stem, refused when the stem
# cannot be written as one.
def principal-for [file: path]: nothing -> string {
    check-signer-name ($file | path parse | get stem) $"($file)"
}

# Refuse a --signer whose key the trust list does not hold.
#
# Why an error rather than a negative verdict: "alice did not sign this" is a
# claim, and a verifier without alice's key cannot make it — the honest answer
# is "I cannot tell". `merkle verify` used to fold the two together and return
# `valid: false` with "no valid signature from signer alice", so a typo in the
# verifier's OWN flag read as evidence against the artifact. Both verify
# commands ask this before any other work. Shared here because the rule being
# applied is this module's: a principal is the stem of a .pub file.
export def check-signer-known [signer: string pubkeys_dir: path]: nothing -> string {
    let known = list-files $pubkeys_dir --suffix ".pub" | each { principal-for $in }
    if (check-signer-name $signer "--signer") not-in $known {
        error make {msg: $"no key for signer ($signer) in ($pubkeys_dir)/ — --signer names a ($signer).pub there, and this verifier cannot say whether ($signer) signed anything without holding their key. Registered: ($known | str join ', ')"}
    }
    $signer
}

# A signer name, refused unless the trust list can express it. Exported
# because `ssh-sign sign` is the other end of the same grammar: it takes the
# name from `--name` or from a pubkey stem and writes it into a `.sig` file
# name, and a name this rejects makes every later `verify` in that repo throw
# while rendering the list. Better to refuse it where it enters.
export def check-signer-name [name: string context: string]: nothing -> string {
    if ($name | is-empty) {
        error make {msg: $"($context): there is no signer name to use"}
    }
    if ($name =~ $FORBIDDEN_IN_PRINCIPAL) {
        error make {msg: $"($context): a signer name cannot hold whitespace, quotes, `#`, `,`, `/`, `\\` or the pattern characters `*?!` — got ($name | to nuon)"}
    }
    $name
}
