from crypto._common import bytes_to_hex
from crypto.hmac import (
    HMAC_SHA256,
    HMAC_SHA384,
    HMAC_SHA512,
    hmac_sha256,
    hmac_sha384,
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


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
