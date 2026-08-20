from crypto._common import HashFunction
from crypto.hmac import HMAC, hmac
from crypto.sha256 import SHA256
from crypto.sha512 import SHA384, SHA512
from std.collections import List, Span


def extract[
    H: HashFunction
](salt: Span[Byte, _], input_key_material: Span[Byte, _]) -> List[UInt8]:
    # HMAC zero-pads short keys, so an empty salt already behaves as the
    # RFC 5869 default of digest_size zero bytes.
    return hmac[H](salt, input_key_material)


def expand[
    H: HashFunction
](
    pseudorandom_key: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    if length < 0 or length > 255 * H.digest_size:
        raise Error("HKDF output length is out of range")

    var keyed = HMAC[H](pseudorandom_key)
    var output = List[UInt8](capacity=length)
    var previous = List[UInt8]()
    var counter = 1
    while len(output) < length:
        var mac = keyed.copy()
        mac.update_bytes(previous[:])
        mac.update_bytes(info)
        var suffix = InlineArray[UInt8, 1](fill=UInt8(counter))
        mac.update_bytes(Span(suffix))
        previous = mac^.digest()
        var take = min(len(previous), length - len(output))
        for i in range(take):
            output.append(previous[i])
        counter += 1
    return output^


def derive[
    H: HashFunction
](
    input_key_material: Span[Byte, _],
    salt: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    var pseudorandom_key = extract[H](salt, input_key_material)
    return expand[H](pseudorandom_key[:], info, length)


def extract_sha256(
    salt: Span[Byte, _], input_key_material: Span[Byte, _]
) -> List[UInt8]:
    return extract[SHA256](salt, input_key_material)


def extract_sha384(
    salt: Span[Byte, _], input_key_material: Span[Byte, _]
) -> List[UInt8]:
    return extract[SHA384](salt, input_key_material)


def extract_sha512(
    salt: Span[Byte, _], input_key_material: Span[Byte, _]
) -> List[UInt8]:
    return extract[SHA512](salt, input_key_material)


def expand_sha256(
    pseudorandom_key: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    return expand[SHA256](pseudorandom_key, info, length)


def expand_sha384(
    pseudorandom_key: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    return expand[SHA384](pseudorandom_key, info, length)


def expand_sha512(
    pseudorandom_key: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    return expand[SHA512](pseudorandom_key, info, length)


def derive_sha256(
    input_key_material: Span[Byte, _],
    salt: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    return derive[SHA256](input_key_material, salt, info, length)


def derive_sha384(
    input_key_material: Span[Byte, _],
    salt: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    return derive[SHA384](input_key_material, salt, info, length)


def derive_sha512(
    input_key_material: Span[Byte, _],
    salt: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]:
    return derive[SHA512](input_key_material, salt, info, length)
