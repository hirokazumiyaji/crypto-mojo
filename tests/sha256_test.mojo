from crypto.sha256 import SHA224, SHA256
from std.collections import List
from std.testing import TestSuite, assert_equal


def test_sha256_empty() raises:
    var hasher = SHA256()
    assert_equal(
        hasher^.hexdigest(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )


def test_sha256_known_answers() raises:
    var hasher_a = SHA256()
    hasher_a.update_bytes("a".as_bytes())
    assert_equal(
        hasher_a^.hexdigest(),
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    )

    var hasher_abc = SHA256()
    hasher_abc.update_bytes("abc".as_bytes())
    assert_equal(
        hasher_abc^.hexdigest(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )

    var hasher_digest = SHA256()
    hasher_digest.update_bytes("message digest".as_bytes())
    assert_equal(
        hasher_digest^.hexdigest(),
        "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
    )

    var hasher_alphabet = SHA256()
    hasher_alphabet.update_bytes("abcdefghijklmnopqrstuvwxyz".as_bytes())
    assert_equal(
        hasher_alphabet^.hexdigest(),
        "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
    )


def test_sha256_multiple_blocks_and_uneven_updates() raises:
    var input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    var bytes = input.as_bytes()
    var hasher = SHA256()
    var start = 0
    var width = 1
    while start < len(bytes):
        var end = min(start + width, len(bytes))
        hasher.update_bytes(bytes[start:end])
        start = end
        width = (width % 13) + 1
    assert_equal(
        hasher^.hexdigest(),
        "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
    )


def test_sha256_binary_input() raises:
    var input = List[UInt8]()
    input.append(0x00)
    input.append(0x01)
    input.append(0x02)
    input.append(0x7F)
    input.append(0x80)
    input.append(0xFE)
    input.append(0xFF)
    var hasher = SHA256()
    hasher.update_bytes(input[:])
    assert_equal(
        hasher^.hexdigest(),
        "7bb6463b30f9e301fed333cdf8960ca9497b602ccd8eeb46ae42693fdea15a4d",
    )


def test_sha256_empty_updates() raises:
    var empty = List[UInt8]()
    var input = "abc".as_bytes()
    var hasher = SHA256()
    hasher.update_bytes(empty[:])
    hasher.update_bytes(input[:1])
    hasher.update_bytes(empty[:])
    hasher.update_bytes(input[1:])
    hasher.update_bytes(empty[:])
    assert_equal(
        hasher^.hexdigest(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )


def test_sha256_partial_buffer_then_large_update() raises:
    var large_input = _repeated_a(129)
    var prefix = "abc".as_bytes()
    var hasher = SHA256()
    hasher.update_bytes(prefix)
    hasher.update_bytes(large_input[:])
    assert_equal(
        hasher^.hexdigest(),
        "f9108823e64ef0af81c3249f5174615ab838c2a00f0cfc36abbf009163960564",
    )


def test_sha256_digest_length() raises:
    var digest = SHA256().digest()
    assert_equal(len(digest), 32)


def _repeated_a(length: Int) -> List[UInt8]:
    var input = List[UInt8](capacity=length)
    for _ in range(length):
        input.append(0x61)
    return input^


def test_sha256_padding_boundaries() raises:
    var lengths = [55, 56, 57, 63, 64, 65, 127, 128, 129]
    var expected = [
        "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
        "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
        "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6",
        "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
        "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
        "c57e9278af78fa3cab38667bef4ce29d783787a2f731d4e12200270f0c32320a",
        "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e",
        "c12cb024a2e5551cca0e08fce8f1c5e314555cc3fef6329ee994a3db752166ae",
    ]
    for i in range(len(lengths)):
        var input = _repeated_a(lengths[i])
        var hasher = SHA256()
        if i % 2 == 0:
            hasher.update_bytes(input[:])
        else:
            var split = lengths[i] // 2
            hasher.update_bytes(input[:split])
            hasher.update_bytes(input[split:])
        assert_equal(hasher^.hexdigest(), expected[i])


def test_sha256_one_million_a() raises:
    var input = _repeated_a(1_000_000)
    var hasher = SHA256()
    hasher.update_bytes(input[:])
    assert_equal(
        hasher^.hexdigest(),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    )


def test_sha256_finish_endianness() raises:
    var empty = SHA256()
    assert_equal(empty^.finish(), 16406829232824261652)

    var short = SHA256()
    short.update_bytes("abc".as_bytes())
    assert_equal(short^.finish(), 13436514500253700074)

    var multi_block = SHA256()
    var input = _repeated_a(1000)
    multi_block.update_bytes(input[:])
    assert_equal(multi_block^.finish(), 4750713646703962329)


def test_sha256_standard_hasher_finish() raises:
    var hasher = SHA256()
    UInt32(42).__hash__(hasher)
    var value = hasher^.finish()
    assert_equal(value, 12014217582344364938)


def test_sha224_empty() raises:
    var hasher = SHA224()
    assert_equal(
        hasher^.hexdigest(),
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    )


def test_sha224_abc() raises:
    var hasher = SHA224()
    hasher.update_bytes("abc".as_bytes())
    assert_equal(
        hasher^.hexdigest(),
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    )


def test_sha224_split_update_matches_one_shot() raises:
    var input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    var bytes = input.as_bytes()
    var expected = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"

    var one_shot = SHA224()
    one_shot.update_bytes(bytes)
    assert_equal(one_shot^.hexdigest(), expected)

    var split = SHA224()
    var start = 0
    var width = 1
    while start < len(bytes):
        var end = min(start + width, len(bytes))
        split.update_bytes(bytes[start:end])
        start = end
        width = (width % 13) + 1
    assert_equal(split^.hexdigest(), expected)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
