from crypto.hmac import (
    HMAC_SHA256,
    HMAC_SHA384,
    HMAC_SHA512,
    hmac_sha256,
    hmac_sha384,
    hmac_sha512,
)
from std.collections import List, Span


def extract_sha256(
    salt: Span[Byte, _], input_key_material: Span[Byte, _]
) -> List[UInt8]:
    if len(salt) == 0:
        var zero_salt = List[UInt8](length=32, fill=0)
        return hmac_sha256(zero_salt[:], input_key_material)
    return hmac_sha256(salt, input_key_material)


def extract_sha384(
    salt: Span[Byte, _], input_key_material: Span[Byte, _]
) -> List[UInt8]:
    if len(salt) == 0:
        var zero_salt = List[UInt8](length=48, fill=0)
        return hmac_sha384(zero_salt[:], input_key_material)
    return hmac_sha384(salt, input_key_material)


def extract_sha512(
    salt: Span[Byte, _], input_key_material: Span[Byte, _]
) -> List[UInt8]:
    if len(salt) == 0:
        var zero_salt = List[UInt8](length=64, fill=0)
        return hmac_sha512(zero_salt[:], input_key_material)
    return hmac_sha512(salt, input_key_material)


def expand_sha256(
    pseudorandom_key: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    if length < 0 or length > 255 * 32:
        raise Error("HKDF-SHA-256 output length is out of range")

    var output = List[UInt8](capacity=length)
    var previous = List[UInt8]()
    var counter = 1
    while len(output) < length:
        var mac = HMAC_SHA256(pseudorandom_key)
        if len(previous) > 0:
            mac.update_bytes(previous[:])
        mac.update_bytes(info)
        var suffix = List[UInt8](capacity=1)
        suffix.append(UInt8(counter))
        mac.update_bytes(suffix[:])
        previous = mac^.digest()
        for i in range(len(previous)):
            if len(output) == length:
                break
            output.append(previous[i])
        counter += 1
    return output^


def expand_sha384(
    pseudorandom_key: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    if length < 0 or length > 255 * 48:
        raise Error("HKDF-SHA-384 output length is out of range")

    var output = List[UInt8](capacity=length)
    var previous = List[UInt8]()
    var counter = 1
    while len(output) < length:
        var mac = HMAC_SHA384(pseudorandom_key)
        if len(previous) > 0:
            mac.update_bytes(previous[:])
        mac.update_bytes(info)
        var suffix = List[UInt8](capacity=1)
        suffix.append(UInt8(counter))
        mac.update_bytes(suffix[:])
        previous = mac^.digest()
        for i in range(len(previous)):
            if len(output) == length:
                break
            output.append(previous[i])
        counter += 1
    return output^


def expand_sha512(
    pseudorandom_key: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    if length < 0 or length > 255 * 64:
        raise Error("HKDF-SHA-512 output length is out of range")

    var output = List[UInt8](capacity=length)
    var previous = List[UInt8]()
    var counter = 1
    while len(output) < length:
        var mac = HMAC_SHA512(pseudorandom_key)
        if len(previous) > 0:
            mac.update_bytes(previous[:])
        mac.update_bytes(info)
        var suffix = List[UInt8](capacity=1)
        suffix.append(UInt8(counter))
        mac.update_bytes(suffix[:])
        previous = mac^.digest()
        for i in range(len(previous)):
            if len(output) == length:
                break
            output.append(previous[i])
        counter += 1
    return output^


def derive_sha256(
    input_key_material: Span[Byte, _],
    salt: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    if length < 0 or length > 255 * 32:
        raise Error("HKDF-SHA-256 output length is out of range")
    var pseudorandom_key = extract_sha256(salt, input_key_material)
    return expand_sha256(pseudorandom_key[:], info, length)


def derive_sha384(
    input_key_material: Span[Byte, _],
    salt: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    if length < 0 or length > 255 * 48:
        raise Error("HKDF-SHA-384 output length is out of range")
    var pseudorandom_key = extract_sha384(salt, input_key_material)
    return expand_sha384(pseudorandom_key[:], info, length)


def derive_sha512(
    input_key_material: Span[Byte, _],
    salt: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    if length < 0 or length > 255 * 64:
        raise Error("HKDF-SHA-512 output length is out of range")
    var pseudorandom_key = extract_sha512(salt, input_key_material)
    return expand_sha512(pseudorandom_key[:], info, length)
