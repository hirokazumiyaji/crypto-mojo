from crypto.blake2b import BLAKE2b
from std.collections import List
from std.testing import TestSuite, assert_equal


def test_blake2b_empty() raises:
    var hasher = BLAKE2b()
    assert_equal(
        hasher^.hexdigest(),
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
    )


def test_blake2b_known_answers() raises:
    var hasher_abc = BLAKE2b()
    hasher_abc.update_bytes("abc".as_bytes())
    assert_equal(
        hasher_abc^.hexdigest(),
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    )

    var hasher_abc_256 = BLAKE2b(digest_size=32)
    hasher_abc_256.update_bytes("abc".as_bytes())
    assert_equal(
        hasher_abc_256^.hexdigest(),
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    )


def test_blake2b_streaming_updates() raises:
    var input = _repeated_a(1000)
    var hasher = BLAKE2b()
    var start = 0
    var width = 1
    while start < len(input):
        var end = min(start + width, len(input))
        hasher.update_bytes(input[start:end])
        start = end
        width = (width % 19) + 1
    assert_equal(
        hasher^.hexdigest(),
        "d6a69459fe93fc6b9537ed4336e5099e0dcca3e97290a412500ed7a0daffb03d80cf3650a20e0591f748e10c3c534945ee83d5f2c9722f1a68d98b8c01af23fd",
    )


def test_blake2b_binary_input() raises:
    var input = List[UInt8]()
    input.append(0x00)
    input.append(0x01)
    input.append(0x02)
    input.append(0x7F)
    input.append(0x80)
    input.append(0xFE)
    input.append(0xFF)
    var hasher = BLAKE2b()
    hasher.update_bytes(input[:])
    assert_equal(
        hasher^.hexdigest(),
        "df26105e90e7faf6bb104d7444ef5a7ce368d91b9270e2e366b7ce7d91cb4ea614f9f05242a7d1b89c507b3dfbb6985f1e37ad5dda969f3cf5260d2eed909eb9",
    )


def test_blake2b_block_boundaries() raises:
    var lengths = [127, 128, 129, 255, 256, 257]
    var expected = [
        "94596b9d6199c807c40ae1a935f3633ba5a8dd5655f7f1bd44f5285b1ce8dbb0054771eba409539df85a963296d28788807105153c90fa3ec3d761228e90f8b8",
        "fc6c71f688f43ea7d60817478808f3cac753e61571865c95adbc2d9122c943a76b92c2cb1047ef3fe7bf6e436ec1d0a99a9e5b216780bf7fed9d7ca91d3a8f3b",
        "55e6e0eb418149a8af92fd9ddc99254781b2f522a131b4f4d984404b71a00e1167b8124d5dcddd4c6977b299392335d6edd303da6d344d74bbef2d38101b232b",
        "792ea4793169359d36f13f472d4b427b40c663c680f47932a0cf3a110e6d84305f46825da8ada4d83a6247bb09fb3bb1b5781186a81b2aff8c9c39a597e447dd",
        "0eee13d0c73a2710c5015a8b4be0a16120bb88f826b662951ffe4b3b81441cfdce1f712c58e237dba72a0dad7f9c86b9745ea0b4b3b850ff3a260fb7df9d3e81",
        "0d686cbcff66401ab36b8a8e7fcf4085319eb296eaa55c4470c36bccaff2ecd4b3572c32ed48e8bb97cc5d08302a79b3a26e751feb7f565b19fa0d8f65247dd1",
    ]
    for i in range(len(lengths)):
        var input = _repeated_a(lengths[i])
        var hasher = BLAKE2b()
        if i % 2 == 0:
            hasher.update_bytes(input[:])
        else:
            var split = lengths[i] // 2
            hasher.update_bytes(input[:split])
            hasher.update_bytes(input[split:])
        assert_equal(hasher^.hexdigest(), expected[i])


def test_blake2b_digest_lengths() raises:
    var digest_512 = BLAKE2b().digest()
    assert_equal(len(digest_512), 64)
    var digest_256 = BLAKE2b(digest_size=32).digest()
    assert_equal(len(digest_256), 32)


def test_blake2b_finish() raises:
    var empty = BLAKE2b()
    assert_equal(empty^.finish(), 241225442164632184)

    var short = BLAKE2b()
    short.update_bytes("abc".as_bytes())
    assert_equal(short^.finish(), 958453735928201402)


def _repeated_a(length: Int) -> List[UInt8]:
    var input = List[UInt8](capacity=length)
    for _ in range(length):
        input.append(0x61)
    return input^


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
