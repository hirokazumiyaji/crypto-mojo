from crypto._common import HashFunction, bytes_to_hex
from crypto.blake2b import BLAKE2b
from crypto.blake3 import BLAKE3
from crypto.sha256 import SHA256
from crypto.sha3 import SHA3_256
from crypto.sha512 import SHA384, SHA512
from crypto.subtle import constant_time_compare
from std.collections import List, Span


struct HMAC[H: HashFunction](Copyable, Movable):
    var _inner: Self.H
    var _outer: Self.H
    var _inner_init: Self.H

    def __init__(out self, key: Span[Byte, _]):
        var block = Array[UInt8, Self.H.block_size](fill=0)
        if len(key) > Self.H.block_size:
            var hasher = Self.H()
            hasher.update_bytes(key)
            var digest = hasher^.digest()
            for i in range(len(digest)):
                block[i] = digest[i]
        else:
            for i in range(len(key)):
                block[i] = key[i]
        for i in range(Self.H.block_size):
            block[i] ^= 0x36
        self._inner = Self.H()
        self._inner.update_bytes(Span(block))
        for i in range(Self.H.block_size):
            block[i] ^= 0x36 ^ 0x5C
        self._outer = Self.H()
        self._outer.update_bytes(Span(block))
        self._inner_init = self._inner.copy()

    def update_bytes(mut self, data: Span[Byte, _]):
        self._inner.update_bytes(data)

    def clone(self) -> Self:
        return self.copy()

    def reset(mut self):
        # `_outer` is only ever consumed (moved out) by `digest`, which ends
        # `self`'s lifetime, so it never diverges from its constructed value
        # and needs no snapshot to restore.
        self._inner = self._inner_init.copy()

    def digest(deinit self) -> List[UInt8]:
        var inner = self._inner^
        var outer = self._outer^
        var inner_digest = inner^.digest()
        outer.update_bytes(inner_digest[:])
        return outer^.digest()

    def hexdigest(deinit self) -> String:
        return bytes_to_hex(self^.digest())

    def verify(deinit self, expected: Span[Byte, _]) -> Bool:
        var actual = self^.digest()
        return constant_time_compare(actual[:], expected)


comptime HMAC_SHA256 = HMAC[SHA256]
comptime HMAC_SHA384 = HMAC[SHA384]
comptime HMAC_SHA512 = HMAC[SHA512]
comptime HMAC_SHA3_256 = HMAC[SHA3_256]
comptime HMAC_BLAKE2b = HMAC[BLAKE2b]
comptime HMAC_BLAKE3 = HMAC[BLAKE3]


def hmac[
    H: HashFunction
](key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]:
    var mac = HMAC[H](key)
    mac.update_bytes(data)
    return mac^.digest()


def hmac_sha256(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]:
    return hmac[SHA256](key, data)


def hmac_sha384(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]:
    return hmac[SHA384](key, data)


def hmac_sha512(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]:
    return hmac[SHA512](key, data)


def hmac_sha3_256(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]:
    return hmac[SHA3_256](key, data)


def hmac_blake2b(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]:
    return hmac[BLAKE2b](key, data)


def hmac_blake3(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]:
    return hmac[BLAKE3](key, data)
