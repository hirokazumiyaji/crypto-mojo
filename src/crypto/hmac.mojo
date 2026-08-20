from crypto._common import bytes_to_hex
from crypto.sha256 import SHA256
from crypto.sha512 import SHA384, SHA512
from crypto.subtle import constant_time_compare
from std.collections import List, Span


def _sha256_key_block(key: Span[Byte, _]) -> List[UInt8]:
    var block = List[UInt8](length=64, fill=0)
    if len(key) > 64:
        var hasher = SHA256()
        hasher.update_bytes(key)
        var digest = hasher^.digest()
        for i in range(len(digest)):
            block[i] = digest[i]
    else:
        for i in range(len(key)):
            block[i] = key[i]
    return block^


def _sha384_key_block(key: Span[Byte, _]) -> List[UInt8]:
    var block = List[UInt8](length=128, fill=0)
    if len(key) > 128:
        var hasher = SHA384()
        hasher.update_bytes(key)
        var digest = hasher^.digest()
        for i in range(len(digest)):
            block[i] = digest[i]
    else:
        for i in range(len(key)):
            block[i] = key[i]
    return block^


def _sha512_key_block(key: Span[Byte, _]) -> List[UInt8]:
    var block = List[UInt8](length=128, fill=0)
    if len(key) > 128:
        var hasher = SHA512()
        hasher.update_bytes(key)
        var digest = hasher^.digest()
        for i in range(len(digest)):
            block[i] = digest[i]
    else:
        for i in range(len(key)):
            block[i] = key[i]
    return block^


struct HMAC_SHA256(Movable):
    var _inner: SHA256
    var _outer: SHA256

    def __init__(out self, key: Span[Byte, _]):
        var block = _sha256_key_block(key)
        var inner_pad = List[UInt8](length=64, fill=0)
        var outer_pad = List[UInt8](length=64, fill=0)
        for i in range(64):
            inner_pad[i] = block[i] ^ 0x36
            outer_pad[i] = block[i] ^ 0x5C
        self._inner = SHA256()
        self._inner.update_bytes(inner_pad[:])
        self._outer = SHA256()
        self._outer.update_bytes(outer_pad[:])

    def update_bytes(mut self, data: Span[Byte, _]):
        self._inner.update_bytes(data)

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


def hmac_sha256(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]:
    var mac = HMAC_SHA256(key)
    mac.update_bytes(data)
    return mac^.digest()


struct HMAC_SHA384(Movable):
    var _inner: SHA384
    var _outer: SHA384

    def __init__(out self, key: Span[Byte, _]):
        var block = _sha384_key_block(key)
        var inner_pad = List[UInt8](length=128, fill=0)
        var outer_pad = List[UInt8](length=128, fill=0)
        for i in range(128):
            inner_pad[i] = block[i] ^ 0x36
            outer_pad[i] = block[i] ^ 0x5C
        self._inner = SHA384()
        self._inner.update_bytes(inner_pad[:])
        self._outer = SHA384()
        self._outer.update_bytes(outer_pad[:])

    def update_bytes(mut self, data: Span[Byte, _]):
        self._inner.update_bytes(data)

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


def hmac_sha384(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]:
    var mac = HMAC_SHA384(key)
    mac.update_bytes(data)
    return mac^.digest()


struct HMAC_SHA512(Movable):
    var _inner: SHA512
    var _outer: SHA512

    def __init__(out self, key: Span[Byte, _]):
        var block = _sha512_key_block(key)
        var inner_pad = List[UInt8](length=128, fill=0)
        var outer_pad = List[UInt8](length=128, fill=0)
        for i in range(128):
            inner_pad[i] = block[i] ^ 0x36
            outer_pad[i] = block[i] ^ 0x5C
        self._inner = SHA512()
        self._inner.update_bytes(inner_pad[:])
        self._outer = SHA512()
        self._outer.update_bytes(outer_pad[:])

    def update_bytes(mut self, data: Span[Byte, _]):
        self._inner.update_bytes(data)

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


def hmac_sha512(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]:
    var mac = HMAC_SHA512(key)
    mac.update_bytes(data)
    return mac^.digest()
