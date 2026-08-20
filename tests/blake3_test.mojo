from crypto.blake3 import BLAKE3
from std.collections import List
from std.testing import TestSuite, assert_equal


def test_blake3_empty() raises:
    var hasher = BLAKE3()
    assert_equal(
        hasher^.hexdigest(),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    )


def test_blake3_chunk_boundaries() raises:
    var lengths = [1, 63, 64, 65, 1023, 1024, 1025, 2048, 2049]
    var expected = [
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
        "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
        "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
        "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
        "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
    ]
    for i in range(len(lengths)):
        var input = _pattern(lengths[i])
        var hasher = BLAKE3()
        hasher.update_bytes(input[:])
        assert_equal(hasher^.hexdigest(), expected[i])


def test_blake3_streaming_updates() raises:
    var input = _pattern(4097)
    var hasher = BLAKE3()
    var start = 0
    var width = 1
    while start < len(input):
        var end = min(start + width, len(input))
        hasher.update_bytes(input[start:end])
        start = end
        width = (width % 23) + 1
    assert_equal(
        hasher^.hexdigest(),
        "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995",
    )


def test_blake3_keyed_hash() raises:
    var key = "whats the Elvish word for friend".as_bytes()
    var hasher = BLAKE3(key)
    assert_equal(
        hasher^.hexdigest(),
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
    )


def test_blake3_xof() raises:
    var hasher = BLAKE3()
    assert_equal(
        hasher^.hexdigest_xof(100),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e",
    )
    var digest = BLAKE3().digest_xof(100)
    assert_equal(len(digest), 100)


def test_blake3_finish() raises:
    var hasher = BLAKE3()
    assert_equal(hasher^.finish(), 12007152915317330863)


def _pattern(length: Int) -> List[UInt8]:
    var input = List[UInt8](capacity=length)
    for i in range(length):
        input.append((i % 251).cast[DType.uint8]())
    return input^


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
