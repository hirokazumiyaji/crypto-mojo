from crypto.sha1 import SHA1
from std.testing import TestSuite, assert_equal


def test_sha1_empty() raises:
    var hasher = SHA1()
    assert_equal(
        hasher^.hexdigest(),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    )


def test_sha1_abc() raises:
    var hasher = SHA1()
    hasher.update_bytes("abc".as_bytes())
    assert_equal(
        hasher^.hexdigest(),
        "a9993e364706816aba3e25717850c26c9cd0d89d",
    )


def test_sha1_split_update() raises:
    var hasher = SHA1()
    hasher.update_bytes("ab".as_bytes())
    hasher.update_bytes("c".as_bytes())
    assert_equal(
        hasher^.hexdigest(),
        "a9993e364706816aba3e25717850c26c9cd0d89d",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
