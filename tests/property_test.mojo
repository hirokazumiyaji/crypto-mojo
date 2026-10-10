from crypto.hkdf import expand_sha256, extract_sha256, reader_sha256
from crypto.sha256 import SHA256
from proptest import Settings, TestCase, for_all, integers
from std.collections import List
from std.testing import TestSuite, assert_equal


def _sha256_chunking_matches_one_shot(mut tc: TestCase) raises:
    var length = tc.draw(integers(0, 256), "length")
    var input = List[UInt8](capacity=length)
    for _ in range(length):
        input.append(UInt8(tc.draw(integers(0, 255), "byte")))

    var expected = SHA256()
    expected.update_bytes(input[:])

    var chunked = SHA256()
    var offset = 0
    while offset < length:
        var chunk_size = tc.draw(integers(1, 80), "chunk_size")
        var end = min(offset + chunk_size, length)
        chunked.update_bytes(input[offset:end])
        offset = end

    assert_equal(chunked^.digest(), expected^.digest())


def _hkdf_reader_chunking_matches_expand(mut tc: TestCase) raises:
    var ikm = "property-based input key material".as_bytes()
    var salt = "property-based salt".as_bytes()
    var info = "property-based context".as_bytes()
    var prk = extract_sha256(salt, ikm)
    var length = tc.draw(integers(0, 128), "length")
    var expected = expand_sha256(prk[:], info, length)
    var reader = reader_sha256(prk[:], info)
    var actual = List[UInt8](capacity=length)

    while len(actual) < length:
        var remaining = length - len(actual)
        var chunk_size = tc.draw(integers(1, remaining), "chunk_size")
        var chunk = reader.read(chunk_size)
        for byte in chunk:
            actual.append(byte)

    assert_equal(actual, expected)


def test_sha256_chunking_property() raises:
    for_all(
        _sha256_chunking_matches_one_shot,
        Settings(seed=UInt64(1), max_examples=100),
    )


def test_hkdf_reader_chunking_property() raises:
    for_all(
        _hkdf_reader_chunking_matches_expand,
        Settings(seed=UInt64(2), max_examples=100),
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
