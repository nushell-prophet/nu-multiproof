# Render an OpenSSH allowed_signers body from every *.pub in a directory.
# Shared by ssh-sign verify (named principals so find-principals returns the
# signer) and git-proof (wildcard principal for collective commit-signing trust).

# One line per pubkey: `<principal> namespaces="<namespace>" <key>`.
# --wildcard uses "*" for every key (a collective trust statement); otherwise
# each key's filename stem is its principal.
export def allowed-signers-body [
    pubkeys_dir: path
    --namespace: string = "file"
    --wildcard # use "*" as the principal for every key instead of its stem
]: nothing -> string {
    glob ($pubkeys_dir | path join "*.pub")
    | each {|file|
        let key = (open --raw $file | str trim)
        let principal = if $wildcard { "*" } else { $file | path parse | get stem }
        $"($principal) namespaces=\"($namespace)\" ($key)"
    }
    | str join "\n"
}
