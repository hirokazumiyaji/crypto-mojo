from crypto._common import bytes_to_hex
from crypto.hkdf import (
    HKDF_SHA256,
    derive_sha256,
    derive_sha384,
    derive_sha512,
    expand_sha256,
    expand_sha384,
    expand_sha512,
    extract_sha256,
    extract_sha384,
    extract_sha512,
    reader_sha256,
)
from std.collections import List
from std.testing import TestSuite, assert_equal, assert_raises


def _repeated_byte(value: UInt8, length: Int) -> List[UInt8]:
    return List[UInt8](length=length, fill=value)


def _ascending_bytes(start: UInt8, length: Int) -> List[UInt8]:
    var output = List[UInt8](capacity=length)
    for i in range(length):
        output.append(UInt8(Int(start) + i))
    return output^


def test_hkdf_sha256_rfc5869_case_1() raises:
    var ikm = _repeated_byte(0x0B, 22)
    var salt = _ascending_bytes(0x00, 13)
    var info = _ascending_bytes(0xF0, 10)
    var expected_prk = (
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    var expected_okm = (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5b"
        "f34007208d5b887185865"
    )

    var prk = extract_sha256(salt[:], ikm[:])
    assert_equal(bytes_to_hex(prk.copy()), expected_prk)
    assert_equal(bytes_to_hex(expand_sha256(prk[:], info[:], 42)), expected_okm)
    assert_equal(
        bytes_to_hex(derive_sha256(ikm[:], salt[:], info[:], 42)),
        expected_okm,
    )


def test_hkdf_sha384_fixed_vector() raises:
    var ikm = _repeated_byte(0x0B, 22)
    var salt = _ascending_bytes(0x00, 13)
    var info = _ascending_bytes(0xF0, 10)
    var expected_prk = (
        "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8de"
        "c70ee9a7e1f3e293ef68eceb072a5ade"
    )
    var expected_okm = (
        "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f7"
        "48b6457763e4f0204fc5"
    )

    var prk = extract_sha384(salt[:], ikm[:])
    assert_equal(bytes_to_hex(prk.copy()), expected_prk)
    assert_equal(bytes_to_hex(expand_sha384(prk[:], info[:], 42)), expected_okm)
    assert_equal(
        bytes_to_hex(derive_sha384(ikm[:], salt[:], info[:], 42)),
        expected_okm,
    )


def test_hkdf_sha512_fixed_vector() raises:
    var ikm = _repeated_byte(0x0B, 22)
    var salt = _ascending_bytes(0x00, 13)
    var info = _ascending_bytes(0xF0, 10)
    var expected_prk = (
        "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26"
        "c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237"
    )
    var expected_okm = (
        "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c14815793"
        "38da362cb8d9f925d7cb"
    )

    var prk = extract_sha512(salt[:], ikm[:])
    assert_equal(bytes_to_hex(prk.copy()), expected_prk)
    assert_equal(bytes_to_hex(expand_sha512(prk[:], info[:], 42)), expected_okm)
    assert_equal(
        bytes_to_hex(derive_sha512(ikm[:], salt[:], info[:], 42)),
        expected_okm,
    )


def test_hkdf_extract_empty_salt_uses_zero_digest_key() raises:
    var empty = List[UInt8]()
    var ikm = "input keying material".as_bytes()
    assert_equal(
        bytes_to_hex(extract_sha256(empty[:], ikm)),
        "364291161024cea0e8a5cf3cbf0ec6230e36f2bf398b574132e6761dd8d0352a",
    )
    assert_equal(
        bytes_to_hex(extract_sha384(empty[:], ikm)),
        (
            "2d23d50654d0ee61771c918bbb44b76ec87b422f634eb4e684c48502e9c3730"
            "4f978ef2f8ba2c5b9aac9929cbb026e39"
        ),
    )
    assert_equal(
        bytes_to_hex(extract_sha512(empty[:], ikm)),
        (
            "46f62bf5ce1c7d2af94f831f6b480027f6d829866bc173418cd09c5ecdb63125"
            "f64a87a3edf8a8576482e0e848a14550d83e8aabec1c5966a26d4fa230e794b9"
        ),
    )


def test_hkdf_sha256_output_length_boundaries() raises:
    var key = "key".as_bytes()
    var info = "info".as_bytes()
    assert_equal(len(expand_sha256(key, info, 0)), 0)
    assert_equal(len(expand_sha256(key, info, 8160)), 8160)
    with assert_raises():
        _ = expand_sha256(key, info, 8161)
    with assert_raises():
        _ = expand_sha256(key, info, -1)


def test_hkdf_reader_matches_expand() raises:
    var prk = extract_sha256(
        _ascending_bytes(0x00, 13)[:], _repeated_byte(0x0B, 22)[:]
    )
    var info = _ascending_bytes(0xF0, 10)
    var reader = reader_sha256(prk[:], info[:])
    assert_equal(reader.read(42), expand_sha256(prk[:], info[:], 42))


def test_hkdf_reader_sequential_reads() raises:
    var prk = extract_sha256(
        _ascending_bytes(0x00, 13)[:], _repeated_byte(0x0B, 22)[:]
    )
    var info = _ascending_bytes(0xF0, 10)
    var full = expand_sha256(prk[:], info[:], 42)
    var reader = HKDF_SHA256(prk[:], info[:])
    var first = reader.read(10)
    var second = reader.read(32)
    var joined = first.copy()
    for b in second:
        joined.append(b)
    assert_equal(joined, full)


def test_hkdf_reader_reset_and_clone() raises:
    var prk = extract_sha256(
        _ascending_bytes(0x00, 13)[:], _repeated_byte(0x0B, 22)[:]
    )
    var info = _ascending_bytes(0xF0, 10)
    var reader = HKDF_SHA256(prk[:], info[:])
    var a = reader.read(8)
    var cloned = reader.clone()
    var b1 = reader.read(8)
    var b2 = cloned.read(8)
    assert_equal(b1, b2)
    reader.reset()
    assert_equal(reader.read(8), a)


def test_hkdf_reader_rejects_over_max() raises:
    var prk = extract_sha256(
        _ascending_bytes(0x00, 13)[:], _repeated_byte(0x0B, 22)[:]
    )
    var info = List[UInt8]()
    var reader = HKDF_SHA256(prk[:], info[:])
    with assert_raises():
        _ = reader.read(255 * 32 + 1)


def test_hkdf_reader_rejects_overflowing_length() raises:
    # A naive `self._emitted + length > max` check wraps around for a huge
    # `length`, making the comparison falsely pass. Read a few bytes first so
    # `self._emitted` is nonzero, then request a length near Int's positive
    # limit that would overflow the addition.
    var prk = extract_sha256(
        _ascending_bytes(0x00, 13)[:], _repeated_byte(0x0B, 22)[:]
    )
    var info = List[UInt8]()
    var reader = HKDF_SHA256(prk[:], info[:])
    _ = reader.read(8)
    with assert_raises():
        _ = reader.read(9223372036854775807)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
