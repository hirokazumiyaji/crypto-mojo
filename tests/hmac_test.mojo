from crypto._common import bytes_to_hex
from crypto.hmac import (
    HMAC_BLAKE2b,
    HMAC_BLAKE3,
    HMAC_SHA256,
    HMAC_SHA384,
    HMAC_SHA3_256,
    HMAC_SHA512,
    hmac_blake2b,
    hmac_blake3,
    hmac_sha256,
    hmac_sha384,
    hmac_sha3_256,
    hmac_sha512,
)
from std.collections import List
from std.testing import TestSuite, assert_equal, assert_false, assert_true


def _repeated_byte(value: UInt8, length: Int) -> List[UInt8]:
    return List[UInt8](length=length, fill=value)


def test_hmac_sha256_rfc4231_case_1() raises:
    var key = _repeated_byte(0x0B, 20)
    var expected = (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )
    var tag = hmac_sha256(key[:], "Hi There".as_bytes())
    assert_equal(bytes_to_hex(tag^), expected)


def test_hmac_sha256_streaming_matches_one_shot() raises:
    var key = _repeated_byte(0x0B, 20)
    var expected = hmac_sha256(key[:], "Hi There".as_bytes())
    var mac = HMAC_SHA256(key[:])
    mac.update_bytes("Hi ".as_bytes())
    mac.update_bytes("There".as_bytes())
    assert_equal(mac^.digest(), expected)


def test_hmac_sha256_verify() raises:
    var key = _repeated_byte(0x0B, 20)
    var tag = hmac_sha256(key[:], "Hi There".as_bytes())
    var verifier = HMAC_SHA256(key[:])
    verifier.update_bytes("Hi There".as_bytes())
    assert_true(verifier^.verify(tag[:]))

    var wrong_tag = tag.copy()
    wrong_tag[0] ^= 0x01
    var wrong_verifier = HMAC_SHA256(key[:])
    wrong_verifier.update_bytes("Hi There".as_bytes())
    assert_false(wrong_verifier^.verify(wrong_tag[:]))

    var short_verifier = HMAC_SHA256(key[:])
    short_verifier.update_bytes("Hi There".as_bytes())
    assert_false(short_verifier^.verify(tag[:31]))


def test_hmac_sha256_empty_key_and_input() raises:
    var empty = List[UInt8]()
    var mac = HMAC_SHA256(empty[:])
    assert_equal(
        mac^.hexdigest(),
        "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
    )


def test_hmac_sha256_hashes_long_key() raises:
    var key = _repeated_byte(0xAA, 131)
    var mac = HMAC_SHA256(key[:])
    mac.update_bytes(
        "Test Using Larger Than Block-Size Key - Hash Key First".as_bytes()
    )
    assert_equal(
        mac^.hexdigest(),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    )


def test_hmac_sha384_rfc4231_case_1() raises:
    var key = _repeated_byte(0x0B, 20)
    var tag = hmac_sha384(key[:], "Hi There".as_bytes())
    assert_equal(
        bytes_to_hex(tag^),
        (
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59"
            "cfaea9ea9076ede7f4af152e8b2fa9cb6"
        ),
    )


def test_hmac_sha384_streaming() raises:
    var key = _repeated_byte(0x0B, 20)
    var mac = HMAC_SHA384(key[:])
    mac.update_bytes("Hi ".as_bytes())
    mac.update_bytes("There".as_bytes())
    assert_equal(
        mac^.hexdigest(),
        (
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59"
            "cfaea9ea9076ede7f4af152e8b2fa9cb6"
        ),
    )


def test_hmac_sha384_verify() raises:
    var key = _repeated_byte(0x0B, 20)
    var tag = hmac_sha384(key[:], "Hi There".as_bytes())
    var verifier = HMAC_SHA384(key[:])
    verifier.update_bytes("Hi There".as_bytes())
    assert_true(verifier^.verify(tag[:]))

    var wrong_tag = tag.copy()
    wrong_tag[0] ^= 0x01
    var wrong_verifier = HMAC_SHA384(key[:])
    wrong_verifier.update_bytes("Hi There".as_bytes())
    assert_false(wrong_verifier^.verify(wrong_tag[:]))

    var short_verifier = HMAC_SHA384(key[:])
    short_verifier.update_bytes("Hi There".as_bytes())
    assert_false(short_verifier^.verify(tag[:47]))


def test_hmac_sha384_hashes_long_key() raises:
    var key = _repeated_byte(0xAA, 131)
    var mac = HMAC_SHA384(key[:])
    mac.update_bytes(
        "Test Using Larger Than Block-Size Key - Hash Key First".as_bytes()
    )
    assert_equal(
        mac^.hexdigest(),
        (
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c"
            "60c2ef6ab4030fe8296248df163f44952"
        ),
    )


def test_hmac_sha512_rfc4231_case_1() raises:
    var key = _repeated_byte(0x0B, 20)
    var tag = hmac_sha512(key[:], "Hi There".as_bytes())
    assert_equal(
        bytes_to_hex(tag^),
        (
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        ),
    )


def test_hmac_sha512_streaming() raises:
    var key = _repeated_byte(0x0B, 20)
    var mac = HMAC_SHA512(key[:])
    mac.update_bytes("Hi ".as_bytes())
    mac.update_bytes("There".as_bytes())
    assert_equal(
        mac^.hexdigest(),
        (
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        ),
    )


def test_hmac_sha512_verify() raises:
    var key = _repeated_byte(0x0B, 20)
    var tag = hmac_sha512(key[:], "Hi There".as_bytes())
    var verifier = HMAC_SHA512(key[:])
    verifier.update_bytes("Hi There".as_bytes())
    assert_true(verifier^.verify(tag[:]))

    var wrong_tag = tag.copy()
    wrong_tag[0] ^= 0x01
    var wrong_verifier = HMAC_SHA512(key[:])
    wrong_verifier.update_bytes("Hi There".as_bytes())
    assert_false(wrong_verifier^.verify(wrong_tag[:]))

    var short_verifier = HMAC_SHA512(key[:])
    short_verifier.update_bytes("Hi There".as_bytes())
    assert_false(short_verifier^.verify(tag[:63]))


def test_hmac_sha512_hashes_long_key() raises:
    var key = _repeated_byte(0xAA, 131)
    var mac = HMAC_SHA512(key[:])
    mac.update_bytes(
        "Test Using Larger Than Block-Size Key - Hash Key First".as_bytes()
    )
    assert_equal(
        mac^.hexdigest(),
        (
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
            "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        ),
    )


def test_hmac_sha3_256_known_answer() raises:
    var key = _repeated_byte(0x0B, 20)
    var tag = hmac_sha3_256(key[:], "Hi There".as_bytes())
    assert_equal(
        bytes_to_hex(tag^),
        "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb",
    )


def test_hmac_sha3_256_streaming_matches_one_shot() raises:
    var key = _repeated_byte(0x0B, 20)
    var expected = hmac_sha3_256(key[:], "Hi There".as_bytes())
    var mac = HMAC_SHA3_256(key[:])
    mac.update_bytes("Hi ".as_bytes())
    mac.update_bytes("There".as_bytes())
    assert_equal(mac^.digest(), expected)


def test_hmac_sha3_256_empty_key() raises:
    var empty = List[UInt8]()
    var tag = hmac_sha3_256(empty[:], "Hi There".as_bytes())
    assert_equal(
        bytes_to_hex(tag^),
        "5a044fcffc9a03239902ac796b2fe369ac4e28c1bf6daaac45b4f495a618ed27",
    )


def test_hmac_sha3_256_hashes_long_key() raises:
    # SHA3-256's block size is 136 bytes, so a 200-byte key must be hashed
    # down before use, exercising the `len(key) > block_size` branch.
    var key = _repeated_byte(0xAA, 200)
    var tag = hmac_sha3_256(
        key[:],
        "Test Using Larger Than Block-Size Key - Hash Key First".as_bytes(),
    )
    assert_equal(
        bytes_to_hex(tag^),
        "49ad92b02124fdac9627ae45e008a696182ab6bfb8470457777c744aeb9df06f",
    )


def test_hmac_sha3_256_verify() raises:
    var key = _repeated_byte(0x0B, 20)
    var tag = hmac_sha3_256(key[:], "Hi There".as_bytes())
    var verifier = HMAC_SHA3_256(key[:])
    verifier.update_bytes("Hi There".as_bytes())
    assert_true(verifier^.verify(tag[:]))

    var wrong_tag = tag.copy()
    wrong_tag[0] ^= 0x01
    var wrong_verifier = HMAC_SHA3_256(key[:])
    wrong_verifier.update_bytes("Hi There".as_bytes())
    assert_false(wrong_verifier^.verify(wrong_tag[:]))

    var short_verifier = HMAC_SHA3_256(key[:])
    short_verifier.update_bytes("Hi There".as_bytes())
    assert_false(short_verifier^.verify(tag[:31]))


def test_hmac_blake2b_known_answer() raises:
    var key = _repeated_byte(0x0B, 20)
    var tag = hmac_blake2b(key[:], "Hi There".as_bytes())
    assert_equal(
        bytes_to_hex(tag^),
        (
            "358a6a184924894fc34bee5680eedf57d84a37bb38832f288e3b27dc63a98cc8"
            "c91e76da476b508bc6b2d408a248857452906e4a20b48c6b4b55d2df0fe1dd24"
        ),
    )


def test_hmac_blake2b_streaming_matches_one_shot() raises:
    var key = _repeated_byte(0x0B, 20)
    var expected = hmac_blake2b(key[:], "Hi There".as_bytes())
    var mac = HMAC_BLAKE2b(key[:])
    mac.update_bytes("Hi ".as_bytes())
    mac.update_bytes("There".as_bytes())
    assert_equal(mac^.digest(), expected)


def test_hmac_blake2b_empty_key() raises:
    var empty = List[UInt8]()
    var tag = hmac_blake2b(empty[:], "Hi There".as_bytes())
    assert_equal(
        bytes_to_hex(tag^),
        (
            "d1cf5916ac03578c219a86de599cb066030fe9a30b32e135ccab447d9ff7f85"
            "defc0d0e1021fb729bb519581651361ef4b4489338419792b2ecf3a913f026fbf"
        ),
    )


def test_hmac_blake2b_hashes_long_key() raises:
    # BLAKE2b's block size is 128 bytes, so a 200-byte key must be hashed
    # down before use, exercising the `len(key) > block_size` branch.
    var key = _repeated_byte(0xAA, 200)
    var tag = hmac_blake2b(
        key[:],
        "Test Using Larger Than Block-Size Key - Hash Key First".as_bytes(),
    )
    assert_equal(
        bytes_to_hex(tag^),
        (
            "2f5f2d35b23f886565d4ef590d7226d15750f0971a39346f2859f38e87f0b09"
            "b871ff0176dfd41c30f2d99e53309e215601088c0299f83f8acd804b32ccea0ae"
        ),
    )


def test_hmac_blake2b_verify() raises:
    var key = _repeated_byte(0x0B, 20)
    var tag = hmac_blake2b(key[:], "Hi There".as_bytes())
    var verifier = HMAC_BLAKE2b(key[:])
    verifier.update_bytes("Hi There".as_bytes())
    assert_true(verifier^.verify(tag[:]))

    var wrong_tag = tag.copy()
    wrong_tag[0] ^= 0x01
    var wrong_verifier = HMAC_BLAKE2b(key[:])
    wrong_verifier.update_bytes("Hi There".as_bytes())
    assert_false(wrong_verifier^.verify(wrong_tag[:]))

    var short_verifier = HMAC_BLAKE2b(key[:])
    short_verifier.update_bytes("Hi There".as_bytes())
    assert_false(short_verifier^.verify(tag[:63]))


def test_hmac_blake3_known_answer() raises:
    var key = _repeated_byte(0x0B, 20)
    var tag = hmac_blake3(key[:], "Hi There".as_bytes())
    assert_equal(
        bytes_to_hex(tag^),
        "0bd71bad2f522a89551e0246a42cd24e960641c71195f33df08ead6af3bbeccb",
    )


def test_hmac_blake3_streaming_matches_one_shot() raises:
    var key = _repeated_byte(0x0B, 20)
    var expected = hmac_blake3(key[:], "Hi There".as_bytes())
    var mac = HMAC_BLAKE3(key[:])
    mac.update_bytes("Hi ".as_bytes())
    mac.update_bytes("There".as_bytes())
    assert_equal(mac^.digest(), expected)


def test_hmac_blake3_empty_key() raises:
    var empty = List[UInt8]()
    var tag = hmac_blake3(empty[:], "Hi There".as_bytes())
    assert_equal(
        bytes_to_hex(tag^),
        "95f962f84fdad94e186d09b1cbae8364f36532eb69c58bfd27235b886c0247e7",
    )


def test_hmac_blake3_hashes_long_key() raises:
    # BLAKE3's block size is 64 bytes, so a 200-byte key must be hashed down
    # before use, exercising the `len(key) > block_size` branch.
    var key = _repeated_byte(0xAA, 200)
    var tag = hmac_blake3(
        key[:],
        "Test Using Larger Than Block-Size Key - Hash Key First".as_bytes(),
    )
    assert_equal(
        bytes_to_hex(tag^),
        "7f3475ec55b84cb8283392b29260fe6b34b9abb9aff44cd5b187c28bd4c3c770",
    )


def test_hmac_blake3_verify() raises:
    var key = _repeated_byte(0x0B, 20)
    var tag = hmac_blake3(key[:], "Hi There".as_bytes())
    var verifier = HMAC_BLAKE3(key[:])
    verifier.update_bytes("Hi There".as_bytes())
    assert_true(verifier^.verify(tag[:]))

    var wrong_tag = tag.copy()
    wrong_tag[0] ^= 0x01
    var wrong_verifier = HMAC_BLAKE3(key[:])
    wrong_verifier.update_bytes("Hi There".as_bytes())
    assert_false(wrong_verifier^.verify(wrong_tag[:]))

    var short_verifier = HMAC_BLAKE3(key[:])
    short_verifier.update_bytes("Hi There".as_bytes())
    assert_false(short_verifier^.verify(tag[:31]))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
