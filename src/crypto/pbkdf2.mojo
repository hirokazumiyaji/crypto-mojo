from crypto.hmac import (
    HMAC_SHA256,
    HMAC_SHA384,
    HMAC_SHA512,
    hmac_sha256,
    hmac_sha384,
    hmac_sha512,
)
from std.collections import List, Span


def _block_count(iterations: Int, length: Int, digest_size: Int) raises -> Int:
    if iterations <= 0:
        raise Error("PBKDF2 iterations must be positive")
    if length < 0:
        raise Error("PBKDF2 output length must not be negative")

    var count = length // digest_size
    if length % digest_size != 0:
        count += 1
    if count > 4_294_967_295:
        raise Error("PBKDF2 output length is too large")
    return count


def _block_suffix(block_index: Int) -> List[UInt8]:
    var suffix = List[UInt8](capacity=4)
    suffix.append(UInt8((block_index >> 24) & 0xFF))
    suffix.append(UInt8((block_index >> 16) & 0xFF))
    suffix.append(UInt8((block_index >> 8) & 0xFF))
    suffix.append(UInt8(block_index & 0xFF))
    return suffix^


def derive_sha256(
    password: Span[Byte, _],
    salt: Span[Byte, _],
    iterations: Int,
    length: Int,
) raises -> List[UInt8]:
    var count = _block_count(iterations, length, 32)
    var output = List[UInt8](capacity=length)
    for block_index in range(1, count + 1):
        var suffix = _block_suffix(block_index)
        var first = HMAC_SHA256(password)
        first.update_bytes(salt)
        first.update_bytes(suffix[:])
        var u = first^.digest()
        var block = u.copy()
        for _ in range(1, iterations):
            var next_u = hmac_sha256(password, u[:])
            u = next_u^
            for i in range(32):
                block[i] ^= u[i]

        for i in range(32):
            if len(output) == length:
                break
            output.append(block[i])
    return output^


def derive_sha384(
    password: Span[Byte, _],
    salt: Span[Byte, _],
    iterations: Int,
    length: Int,
) raises -> List[UInt8]:
    var count = _block_count(iterations, length, 48)
    var output = List[UInt8](capacity=length)
    for block_index in range(1, count + 1):
        var suffix = _block_suffix(block_index)
        var first = HMAC_SHA384(password)
        first.update_bytes(salt)
        first.update_bytes(suffix[:])
        var u = first^.digest()
        var block = u.copy()
        for _ in range(1, iterations):
            var next_u = hmac_sha384(password, u[:])
            u = next_u^
            for i in range(48):
                block[i] ^= u[i]

        for i in range(48):
            if len(output) == length:
                break
            output.append(block[i])
    return output^


def derive_sha512(
    password: Span[Byte, _],
    salt: Span[Byte, _],
    iterations: Int,
    length: Int,
) raises -> List[UInt8]:
    var count = _block_count(iterations, length, 64)
    var output = List[UInt8](capacity=length)
    for block_index in range(1, count + 1):
        var suffix = _block_suffix(block_index)
        var first = HMAC_SHA512(password)
        first.update_bytes(salt)
        first.update_bytes(suffix[:])
        var u = first^.digest()
        var block = u.copy()
        for _ in range(1, iterations):
            var next_u = hmac_sha512(password, u[:])
            u = next_u^
            for i in range(64):
                block[i] ^= u[i]

        for i in range(64):
            if len(output) == length:
                break
            output.append(block[i])
    return output^
