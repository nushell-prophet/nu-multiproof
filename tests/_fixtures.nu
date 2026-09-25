# The per-test temp dir every suite shares. The `_` name keeps nutest from
# picking this up as a suite (discovery matches test_*.nu); import names
# explicitly. nutest discovers the attributes through the import.

use std/testing *

# Why a fixture, not rm at the end of test bodies: after-each runs even when
# the test throws, so a failing test does not leak its /tmp/tmp.* dir.
@before-each
export def setup []: nothing -> record {
    {tmp_dir: (mktemp --directory)}
}

@after-each
export def cleanup [] {
    rm --recursive --force $in.tmp_dir
}
