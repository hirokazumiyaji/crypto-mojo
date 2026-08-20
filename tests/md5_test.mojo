from crypto.md5 import MD5
from std.collections import List
from std.testing import TestSuite, assert_equal


def test_md5_empty() raises:
    var hasher = MD5()
    assert_equal(hasher^.hexdigest(), "d41d8cd98f00b204e9800998ecf8427e")


def test_md5_known_answers() raises:
    var hasher_a = MD5()
    hasher_a.update_bytes("a".as_bytes())
    assert_equal(hasher_a^.hexdigest(), "0cc175b9c0f1b6a831c399e269772661")

    var hasher_abc = MD5()
    hasher_abc.update_bytes("abc".as_bytes())
    assert_equal(hasher_abc^.hexdigest(), "900150983cd24fb0d6963f7d28e17f72")

    var hasher_digest = MD5()
    hasher_digest.update_bytes("message digest".as_bytes())
    assert_equal(hasher_digest^.hexdigest(), "f96b697d7cb7938d525a2f31aaf161d0")

    var hasher_alphabet = MD5()
    hasher_alphabet.update_bytes("abcdefghijklmnopqrstuvwxyz".as_bytes())
    assert_equal(
        hasher_alphabet^.hexdigest(), "c3fcd3d76192e4007dfb496cca67e13b"
    )


def test_md5_multiple_blocks_and_bytewise_updates() raises:
    var input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    var bytes = input.as_bytes()
    var hasher = MD5()
    for i in range(len(bytes)):
        hasher.update_bytes(bytes[i : i + 1])
    assert_equal(hasher^.hexdigest(), "57edf4a22be3c955ac49da2e2107b67a")


def test_md5_binary_input() raises:
    var input = List[UInt8]()
    input.append(0x00)
    input.append(0x01)
    input.append(0x02)
    input.append(0x7F)
    input.append(0x80)
    input.append(0xFE)
    input.append(0xFF)
    var hasher = MD5()
    hasher.update_bytes(input[:])
    assert_equal(hasher^.hexdigest(), "5e3da17bf96438a78b07f4eb06b95d0c")


def test_md5_empty_updates() raises:
    var empty = List[UInt8]()
    var input = "abc".as_bytes()
    var hasher = MD5()
    hasher.update_bytes(empty[:])
    hasher.update_bytes(input[:1])
    hasher.update_bytes(empty[:])
    hasher.update_bytes(input[1:])
    hasher.update_bytes(empty[:])
    assert_equal(hasher^.hexdigest(), "900150983cd24fb0d6963f7d28e17f72")


def test_md5_partial_buffer_then_large_update() raises:
    var large_input = _repeated_a(129)
    var prefix = "abc".as_bytes()
    var hasher = MD5()
    hasher.update_bytes(prefix)
    hasher.update_bytes(large_input[:])
    assert_equal(hasher^.hexdigest(), "b405bb375868d96426223ede73839ff7")


def test_md5_digest_length() raises:
    var digest = MD5().digest()
    assert_equal(len(digest), 16)


def _repeated_a(length: Int) -> List[UInt8]:
    var input = List[UInt8](capacity=length)
    for _ in range(length):
        input.append(0x61)
    return input^


def test_md5_padding_boundaries() raises:
    var lengths = [55, 56, 57, 63, 64, 65, 127, 128, 129]
    var expected = [
        "ef1772b6dff9a122358552954ad0df65",
        "3b0c8ac703f828b04c6c197006d17218",
        "652b906d60af96844ebd21b674f35e93",
        "b06521f39153d618550606be297466d5",
        "014842d480b571495a4a0363793f7367",
        "c743a45e0d2e6a95cb859adae0248435",
        "020406e1d05cdc2aa287641f7ae2cc39",
        "e510683b3f5ffe4093d021808bc6ff70",
        "b325dc1c6f5e7a2b7cf465b9feab7948",
    ]
    for i in range(len(lengths)):
        var input = _repeated_a(lengths[i])
        var hasher = MD5()
        if i % 2 == 0:
            hasher.update_bytes(input[:])
        else:
            var split = lengths[i] // 2
            hasher.update_bytes(input[:split])
            hasher.update_bytes(input[split:])
        assert_equal(hasher^.hexdigest(), expected[i])


def test_md5_one_million_a() raises:
    var input = _repeated_a(1_000_000)
    var hasher = MD5()
    hasher.update_bytes(input[:])
    assert_equal(hasher^.hexdigest(), "7707d6ae4e027c70eea2a935c2296f21")


def test_md5_finish_endianness() raises:
    var empty = MD5()
    assert_equal(empty^.finish(), 338333539836370388)

    var short = MD5()
    short.update_bytes("abc".as_bytes())
    assert_equal(short^.finish(), 12704604231530709392)

    var multi_block = MD5()
    var input = _repeated_a(1000)
    multi_block.update_bytes(input[:])
    assert_equal(multi_block^.finish(), 7375680996756537034)


def test_md5_standard_hasher_finish() raises:
    var hasher = MD5()
    hasher.update(UInt32(42))
    var value = hasher^.finish()
    assert_equal(value, 7885250272287768040)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
