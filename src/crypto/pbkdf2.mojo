from crypto._common import HashFunction
from crypto.hmac import HMAC
from crypto.sha256 import SHA256
from crypto.sha512 import SHA384, SHA512
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


def derive[
    H: HashFunction
](
    password: Span[Byte, _],
    salt: Span[Byte, _],
    iterations: Int,
    length: Int,
) raises -> List[UInt8]:
    var count = _block_count(iterations, length, H.digest_size)
    # Absorbing the password once and copying the keyed state per iteration
    # halves the compression calls versus re-keying HMAC every time.
    var keyed = HMAC[H](password)
    var output = List[UInt8](capacity=length)
    for block_index in range(1, count + 1):
        var first = keyed.copy()
        first.update_bytes(salt)
        var suffix = Array[UInt8, 4](fill=0)
        for i in range(4):
            suffix[i] = UInt8((block_index >> (24 - i * 8)) & 0xFF)
        first.update_bytes(Span(suffix))
        var u = first^.digest()
        var block = u.copy()
        for _ in range(1, iterations):
            var mac = keyed.copy()
            mac.update_bytes(u[:])
            u = mac^.digest()
            for i in range(H.digest_size):
                block[i] ^= u[i]

        var take = min(H.digest_size, length - len(output))
        for i in range(take):
            output.append(block[i])
    return output^


def derive_sha256(
    password: Span[Byte, _],
    salt: Span[Byte, _],
    iterations: Int,
    length: Int,
) raises -> List[UInt8]:
    return derive[SHA256](password, salt, iterations, length)


def derive_sha384(
    password: Span[Byte, _],
    salt: Span[Byte, _],
    iterations: Int,
    length: Int,
) raises -> List[UInt8]:
    return derive[SHA384](password, salt, iterations, length)


def derive_sha512(
    password: Span[Byte, _],
    salt: Span[Byte, _],
    iterations: Int,
    length: Int,
) raises -> List[UInt8]:
    return derive[SHA512](password, salt, iterations, length)
