from crypto.sha1 import SHA1
from std.collections import List
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


def _repeated_a(length: Int) -> List[UInt8]:
    var input = List[UInt8](capacity=length)
    for _ in range(length):
        input.append(0x61)
    return input^


def test_sha1_padding_boundaries() raises:
    var lengths = [55, 56, 64, 65]
    var expected = [
        "c1c8bbdc22796e28c0e15163d20899b65621d65a",
        "c2db330f6083854c99d4b5bfb6e8f29f201be699",
        "0098ba824b5c16427bd7a1122a5a442a25ec644d",
        "11655326c708d70319be2610e8a57d9a5b959d3b",
    ]
    for i in range(len(lengths)):
        var input = _repeated_a(lengths[i])
        var hasher = SHA1()
        if i % 2 == 0:
            hasher.update_bytes(input[:])
        else:
            var split = lengths[i] // 2
            hasher.update_bytes(input[:split])
            hasher.update_bytes(input[split:])
        assert_equal(hasher^.hexdigest(), expected[i])


def test_sha1_multi_block_ascii() raises:
    var input = "The quick brown fox jumps over the lazy dog. " * 3
    var hasher = SHA1()
    hasher.update_bytes(input.as_bytes())
    assert_equal(
        hasher^.hexdigest(),
        "cad36c9a7b06732521999993937a688dbb8f9b99",
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
