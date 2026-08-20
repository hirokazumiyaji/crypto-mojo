from crypto._common import bytes_to_hex
from crypto.hmac import HMAC_SHA256, hmac_sha256
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


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
