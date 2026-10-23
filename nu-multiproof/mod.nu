# Why: the submodules export everything so tests can `use` any helper; this file names the public commands.
# A named list flattens the namespace, so each file's subcommands go through an inline module of the same name,
# and `main` is imported outside it: inside a wrapper module it would surface as `seal seal`, not `seal`.
export use cid-v0.nu [ main ]
export use tree-hashes.nu [ main ]
module tree-hashes { export use tree-hashes.nu [ root-cid ] }
export use tree-hashes
module ots { export use ots.nu [ info stamp upgrade verify ] }
export use ots
module beacon { export use beacon.nu [ latest verify ] }
export use beacon
module merkle { export use merkle.nu [ prove read-root verify write-root ] }
export use merkle
module ssh-sign { export use ssh-sign.nu [ sign verify ] }
export use ssh-sign
module pubkey { export use pubkey.nu [ canonical fingerprint ] }
export use pubkey
export use init.nu [ main ]
export use seal.nu [ main ]
module seal { export use seal.nu [ status ] }
export use seal
