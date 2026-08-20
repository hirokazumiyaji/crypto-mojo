from crypto.blake2b import BLAKE2b
from crypto.blake3 import BLAKE3
from crypto.hkdf import derive_sha256 as hkdf_sha256
from crypto.hmac import hmac_sha256
from crypto.md5 import MD5
from crypto.pbkdf2 import derive_sha256 as pbkdf2_sha256
from crypto.sha256 import SHA256
from crypto.sha3 import SHA3_256
from crypto.sha512 import SHA384, SHA512
from crypto.subtle import constant_time_compare
from std.collections import List
from std.testing import assert_equal, assert_true


comptime _HEX_DIGITS: StaticString = "0123456789abcdef"


def _bytes_to_hex(data: List[UInt8]) -> String:
    var output = String(capacity=2 * len(data))
    for value in data:
        output += String(_HEX_DIGITS[byte=Int(value >> 4)])
        output += String(_HEX_DIGITS[byte=Int(value & 0x0F)])
    return output^


def _repeated_byte(value: UInt8, length: Int) -> List[UInt8]:
    return List[UInt8](length=length, fill=value)


def _ascending_bytes(start: UInt8, length: Int) -> List[UInt8]:
    var output = List[UInt8](capacity=length)
    for i in range(length):
        output.append(UInt8(Int(start) + i))
    return output^


def main() raises:
    var input = "abc".as_bytes()

    var md5 = MD5()
    md5.update_bytes(input)
    assert_equal(md5^.hexdigest(), "900150983cd24fb0d6963f7d28e17f72")

    var sha256 = SHA256()
    sha256.update_bytes(input)
    assert_equal(
        sha256^.hexdigest(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )

    var sha384 = SHA384()
    sha384.update_bytes(input)
    assert_equal(
        sha384^.hexdigest(),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    )

    var sha512 = SHA512()
    sha512.update_bytes(input)
    assert_equal(
        sha512^.hexdigest(),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    )

    var sha3 = SHA3_256()
    sha3.update_bytes(input)
    assert_equal(
        sha3^.hexdigest(),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    )

    var blake2b = BLAKE2b()
    blake2b.update_bytes(input)
    assert_equal(
        blake2b^.hexdigest(),
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    )

    var blake3 = BLAKE3()
    blake3.update_bytes(input)
    assert_equal(
        blake3^.hexdigest(),
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
    )

    var hmac_key = _repeated_byte(0x0B, 20)
    assert_equal(
        _bytes_to_hex(hmac_sha256(hmac_key[:], "Hi There".as_bytes())),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    )

    var ikm = _repeated_byte(0x0B, 22)
    var salt = _ascending_bytes(0x00, 13)
    var info = _ascending_bytes(0xF0, 10)
    assert_equal(
        _bytes_to_hex(hkdf_sha256(ikm[:], salt[:], info[:], 42)),
        (
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5b"
            "f34007208d5b887185865"
        ),
    )

    assert_equal(
        _bytes_to_hex(
            pbkdf2_sha256("passwd".as_bytes(), "salt".as_bytes(), 1, 32)
        ),
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
    )

    assert_true(constant_time_compare("same".as_bytes(), "same".as_bytes()))
