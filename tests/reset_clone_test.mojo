from crypto.blake2b import BLAKE2b
from crypto.blake3 import BLAKE3
from crypto.hmac import HMAC_SHA256, HMAC_SHA3_256, hmac_sha256, hmac_sha3_256
from crypto.md5 import MD5
from crypto.sha1 import SHA1
from crypto.sha256 import SHA224, SHA256
from crypto.sha3 import SHA3_256
from crypto.sha512 import SHA384, SHA512
from std.collections import List
from std.testing import TestSuite, assert_equal, assert_true


def test_sha256_clone_diverges() raises:
    var a = SHA256()
    a.update_bytes("abc".as_bytes())
    var b = a.clone()
    a.update_bytes("d".as_bytes())
    b.update_bytes("e".as_bytes())
    assert_true(a^.hexdigest() != b^.hexdigest())


def test_sha256_reset_replays() raises:
    var hasher = SHA256()
    hasher.update_bytes("abc".as_bytes())
    hasher.reset()
    hasher.update_bytes("abc".as_bytes())
    var fresh = SHA256()
    fresh.update_bytes("abc".as_bytes())
    assert_equal(hasher^.hexdigest(), fresh^.hexdigest())


def test_sha224_clone_diverges() raises:
    var a = SHA224()
    a.update_bytes("abc".as_bytes())
    var b = a.clone()
    a.update_bytes("d".as_bytes())
    b.update_bytes("e".as_bytes())
    assert_true(a^.hexdigest() != b^.hexdigest())


def test_sha224_reset_replays() raises:
    var hasher = SHA224()
    hasher.update_bytes("abc".as_bytes())
    hasher.reset()
    hasher.update_bytes("abc".as_bytes())
    var fresh = SHA224()
    fresh.update_bytes("abc".as_bytes())
    assert_equal(hasher^.hexdigest(), fresh^.hexdigest())


def test_sha1_clone_diverges() raises:
    var a = SHA1()
    a.update_bytes("abc".as_bytes())
    var b = a.clone()
    a.update_bytes("d".as_bytes())
    b.update_bytes("e".as_bytes())
    assert_true(a^.hexdigest() != b^.hexdigest())


def test_sha1_reset_replays() raises:
    var hasher = SHA1()
    hasher.update_bytes("abc".as_bytes())
    hasher.reset()
    hasher.update_bytes("abc".as_bytes())
    var fresh = SHA1()
    fresh.update_bytes("abc".as_bytes())
    assert_equal(hasher^.hexdigest(), fresh^.hexdigest())


def test_md5_clone_diverges() raises:
    var a = MD5()
    a.update_bytes("abc".as_bytes())
    var b = a.clone()
    a.update_bytes("d".as_bytes())
    b.update_bytes("e".as_bytes())
    assert_true(a^.hexdigest() != b^.hexdigest())


def test_md5_reset_replays() raises:
    var hasher = MD5()
    hasher.update_bytes("abc".as_bytes())
    hasher.reset()
    hasher.update_bytes("abc".as_bytes())
    var fresh = MD5()
    fresh.update_bytes("abc".as_bytes())
    assert_equal(hasher^.hexdigest(), fresh^.hexdigest())


def test_sha384_clone_diverges() raises:
    var a = SHA384()
    a.update_bytes("abc".as_bytes())
    var b = a.clone()
    a.update_bytes("d".as_bytes())
    b.update_bytes("e".as_bytes())
    assert_true(a^.hexdigest() != b^.hexdigest())


def test_sha384_reset_replays() raises:
    var hasher = SHA384()
    hasher.update_bytes("abc".as_bytes())
    hasher.reset()
    hasher.update_bytes("abc".as_bytes())
    var fresh = SHA384()
    fresh.update_bytes("abc".as_bytes())
    assert_equal(hasher^.hexdigest(), fresh^.hexdigest())


def test_sha512_clone_diverges() raises:
    var a = SHA512()
    a.update_bytes("abc".as_bytes())
    var b = a.clone()
    a.update_bytes("d".as_bytes())
    b.update_bytes("e".as_bytes())
    assert_true(a^.hexdigest() != b^.hexdigest())


def test_sha512_reset_replays() raises:
    var hasher = SHA512()
    hasher.update_bytes("abc".as_bytes())
    hasher.reset()
    hasher.update_bytes("abc".as_bytes())
    var fresh = SHA512()
    fresh.update_bytes("abc".as_bytes())
    assert_equal(hasher^.hexdigest(), fresh^.hexdigest())


def test_sha3_256_clone_diverges() raises:
    var a = SHA3_256()
    a.update_bytes("abc".as_bytes())
    var b = a.clone()
    a.update_bytes("d".as_bytes())
    b.update_bytes("e".as_bytes())
    assert_true(a^.hexdigest() != b^.hexdigest())


def test_sha3_256_reset_replays() raises:
    var hasher = SHA3_256()
    hasher.update_bytes("abc".as_bytes())
    hasher.reset()
    hasher.update_bytes("abc".as_bytes())
    var fresh = SHA3_256()
    fresh.update_bytes("abc".as_bytes())
    assert_equal(hasher^.hexdigest(), fresh^.hexdigest())


def test_blake2b_clone_diverges() raises:
    var a = BLAKE2b()
    a.update_bytes("abc".as_bytes())
    var b = a.clone()
    a.update_bytes("d".as_bytes())
    b.update_bytes("e".as_bytes())
    assert_true(a^.hexdigest() != b^.hexdigest())


def test_blake2b_reset_replays() raises:
    var hasher = BLAKE2b()
    hasher.update_bytes("abc".as_bytes())
    hasher.reset()
    hasher.update_bytes("abc".as_bytes())
    var fresh = BLAKE2b()
    fresh.update_bytes("abc".as_bytes())
    assert_equal(hasher^.hexdigest(), fresh^.hexdigest())


def test_blake2b_reset_preserves_digest_size() raises:
    var hasher = BLAKE2b(digest_size=32)
    hasher.update_bytes("abc".as_bytes())
    hasher.reset()
    hasher.update_bytes("abc".as_bytes())
    var fresh = BLAKE2b(digest_size=32)
    fresh.update_bytes("abc".as_bytes())
    var replayed = hasher^.digest()
    assert_equal(len(replayed), 32)
    assert_equal(replayed, fresh^.digest())


def test_blake3_clone_diverges() raises:
    var a = BLAKE3()
    a.update_bytes("abc".as_bytes())
    var b = a.clone()
    a.update_bytes("d".as_bytes())
    b.update_bytes("e".as_bytes())
    assert_true(a^.hexdigest() != b^.hexdigest())


def test_blake3_reset_replays() raises:
    var hasher = BLAKE3()
    hasher.update_bytes("abc".as_bytes())
    hasher.reset()
    hasher.update_bytes("abc".as_bytes())
    var fresh = BLAKE3()
    fresh.update_bytes("abc".as_bytes())
    assert_equal(hasher^.hexdigest(), fresh^.hexdigest())


def test_blake3_keyed_reset_preserves_key() raises:
    var key = "whats the Elvish word for friend".as_bytes()
    var hasher = BLAKE3(key)
    hasher.update_bytes("abc".as_bytes())
    hasher.reset()
    hasher.update_bytes("abc".as_bytes())
    var fresh = BLAKE3(key)
    fresh.update_bytes("abc".as_bytes())
    assert_equal(hasher^.hexdigest(), fresh^.hexdigest())


def test_hmac_sha256_clone_diverges() raises:
    var key = List[UInt8](length=20, fill=0x0B)
    var a = HMAC_SHA256(key[:])
    a.update_bytes("Hi There".as_bytes())
    var b = a.clone()
    a.update_bytes("d".as_bytes())
    b.update_bytes("e".as_bytes())
    assert_true(a^.digest() != b^.digest())


def test_hmac_sha256_reset_keeps_keying() raises:
    var key = List[UInt8](length=20, fill=0x0B)
    var mac = HMAC_SHA256(key[:])
    mac.update_bytes("Hi There".as_bytes())
    mac.reset()
    mac.update_bytes("Hi There".as_bytes())
    assert_equal(mac^.digest(), hmac_sha256(key[:], "Hi There".as_bytes()))


def test_hmac_sha3_256_clone_diverges() raises:
    var key = List[UInt8](length=20, fill=0x0B)
    var a = HMAC_SHA3_256(key[:])
    a.update_bytes("Hi There".as_bytes())
    var b = a.clone()
    a.update_bytes("d".as_bytes())
    b.update_bytes("e".as_bytes())
    assert_true(a^.digest() != b^.digest())


def test_hmac_sha3_256_reset_keeps_keying() raises:
    var key = List[UInt8](length=20, fill=0x0B)
    var mac = HMAC_SHA3_256(key[:])
    mac.update_bytes("Hi There".as_bytes())
    mac.reset()
    mac.update_bytes("Hi There".as_bytes())
    assert_equal(mac^.digest(), hmac_sha3_256(key[:], "Hi There".as_bytes()))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
