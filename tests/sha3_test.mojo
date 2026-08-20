from crypto.sha3 import SHA3_256
from std.collections import List
from std.testing import TestSuite, assert_equal


def test_sha3_256_empty() raises:
    var hasher = SHA3_256()
    assert_equal(
        hasher^.hexdigest(),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    )


def test_sha3_256_known_answers() raises:
    var hasher_abc = SHA3_256()
    hasher_abc.update_bytes("abc".as_bytes())
    assert_equal(
        hasher_abc^.hexdigest(),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    )

    var hasher_quick = SHA3_256()
    hasher_quick.update_bytes(
        "The quick brown fox jumps over the lazy dog".as_bytes()
    )
    assert_equal(
        hasher_quick^.hexdigest(),
        "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
    )


def test_sha3_256_streaming_updates() raises:
    var input = _repeated_a(1000)
    var hasher = SHA3_256()
    var start = 0
    var width = 1
    while start < len(input):
        var end = min(start + width, len(input))
        hasher.update_bytes(input[start:end])
        start = end
        width = (width % 19) + 1
    assert_equal(
        hasher^.hexdigest(),
        "8f3934e6f7a15698fe0f396b95d8c4440929a8fa6eae140171c068b4549fbf81",
    )


def test_sha3_256_binary_input() raises:
    var input = List[UInt8]()
    input.append(0x00)
    input.append(0x01)
    input.append(0x02)
    input.append(0x7F)
    input.append(0x80)
    input.append(0xFE)
    input.append(0xFF)
    var hasher = SHA3_256()
    hasher.update_bytes(input[:])
    assert_equal(
        hasher^.hexdigest(),
        "32f54b5485ca85d2a41f9d291d64b067efa38af97dc8dc7bfc01a374f5919d9b",
    )


def test_sha3_256_padding_boundaries() raises:
    var lengths = [135, 136, 137, 271, 272, 273]
    var expected = [
        "8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9",
        "3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1",
        "f8d6846cedd2ccfadf15c5879ef95af724d799eed7391fb1c91f95344e738614",
        "e79e5c6fef1bb5fdea2717ca27e88399e9b64699d1b3eb8e30f314fa055214e8",
        "a490357b9b3fb39d0a89a117734e5b020b1f33c7bf3fa3575c396425432003d3",
        "7930a0e2cde6f949ea52204a2fde51856de566d96d2ebe896656450a2b10b445",
    ]
    for i in range(len(lengths)):
        var input = _repeated_a(lengths[i])
        var hasher = SHA3_256()
        if i % 2 == 0:
            hasher.update_bytes(input[:])
        else:
            var split = lengths[i] // 2
            hasher.update_bytes(input[:split])
            hasher.update_bytes(input[split:])
        assert_equal(hasher^.hexdigest(), expected[i])


def test_sha3_256_digest_length() raises:
    var digest = SHA3_256().digest()
    assert_equal(len(digest), 32)


def test_sha3_256_finish() raises:
    var empty = SHA3_256()
    assert_equal(empty^.finish(), 7410425521722818471)

    var short = SHA3_256()
    short.update_bytes("abc".as_bytes())
    assert_equal(short^.finish(), 12836915144627689530)


def _repeated_a(length: Int) -> List[UInt8]:
    var input = List[UInt8](capacity=length)
    for _ in range(length):
        input.append(0x61)
    return input^


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
