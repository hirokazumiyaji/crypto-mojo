from crypto._common import bytes_to_hex
from crypto.pbkdf2 import derive_sha256, derive_sha384, derive_sha512
from std.testing import TestSuite, assert_equal, assert_raises


def test_pbkdf2_sha256_rfc7914_vector() raises:
    var output = derive_sha256("passwd".as_bytes(), "salt".as_bytes(), 1, 64)
    assert_equal(
        bytes_to_hex(output^),
        (
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        ),
    )


def test_pbkdf2_sha384_fixed_vector() raises:
    var output = derive_sha384("password".as_bytes(), "salt".as_bytes(), 2, 48)
    assert_equal(
        bytes_to_hex(output^),
        (
            "54f775c6d790f21930459162fc535dbf04a939185127016a04176a0730c6f1f4"
            "fb48832ad1261baadd2cedd50814b1c8"
        ),
    )


def test_pbkdf2_sha512_fixed_vector() raises:
    var output = derive_sha512("password".as_bytes(), "salt".as_bytes(), 2, 64)
    assert_equal(
        bytes_to_hex(output^),
        (
            "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c"
            "f76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"
        ),
    )


def test_pbkdf2_truncates_final_block() raises:
    var output = derive_sha256("passwd".as_bytes(), "salt".as_bytes(), 1, 33)
    assert_equal(
        bytes_to_hex(output^),
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49",
    )


def test_pbkdf2_zero_length() raises:
    assert_equal(
        len(derive_sha256("password".as_bytes(), "salt".as_bytes(), 1, 0)),
        0,
    )
    assert_equal(
        len(derive_sha384("password".as_bytes(), "salt".as_bytes(), 1, 0)),
        0,
    )
    assert_equal(
        len(derive_sha512("password".as_bytes(), "salt".as_bytes(), 1, 0)),
        0,
    )


def test_pbkdf2_rejects_non_positive_iterations() raises:
    with assert_raises():
        _ = derive_sha256("password".as_bytes(), "salt".as_bytes(), 0, 32)
    with assert_raises():
        _ = derive_sha384("password".as_bytes(), "salt".as_bytes(), -1, 48)
    with assert_raises():
        _ = derive_sha512("password".as_bytes(), "salt".as_bytes(), 0, 64)


def test_pbkdf2_rejects_negative_length() raises:
    with assert_raises():
        _ = derive_sha256("password".as_bytes(), "salt".as_bytes(), 1, -1)
    with assert_raises():
        _ = derive_sha384("password".as_bytes(), "salt".as_bytes(), 1, -1)
    with assert_raises():
        _ = derive_sha512("password".as_bytes(), "salt".as_bytes(), 1, -1)


def test_pbkdf2_rejects_too_many_blocks() raises:
    with assert_raises():
        _ = derive_sha256(
            "password".as_bytes(), "salt".as_bytes(), 1, 137_438_953_441
        )
    with assert_raises():
        _ = derive_sha384(
            "password".as_bytes(), "salt".as_bytes(), 1, 206_158_430_161
        )
    with assert_raises():
        _ = derive_sha512(
            "password".as_bytes(), "salt".as_bytes(), 1, 274_877_906_881
        )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
