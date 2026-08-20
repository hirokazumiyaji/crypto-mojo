from std.bit import byte_swap, rotate_bits_right
from std.collections import List, Span
from std.hashlib.hasher import Hasher

from ._common import (
    HashFunction,
    append_be_u32,
    bytes_to_hex,
    copy_to_buffer,
    load_le_u32_words,
    simd_lanes_be_u64,
    write_be_u64,
)


comptime _K = [
    UInt32(0x428A2F98),
    UInt32(0x71374491),
    UInt32(0xB5C0FBCF),
    UInt32(0xE9B5DBA5),
    UInt32(0x3956C25B),
    UInt32(0x59F111F1),
    UInt32(0x923F82A4),
    UInt32(0xAB1C5ED5),
    UInt32(0xD807AA98),
    UInt32(0x12835B01),
    UInt32(0x243185BE),
    UInt32(0x550C7DC3),
    UInt32(0x72BE5D74),
    UInt32(0x80DEB1FE),
    UInt32(0x9BDC06A7),
    UInt32(0xC19BF174),
    UInt32(0xE49B69C1),
    UInt32(0xEFBE4786),
    UInt32(0x0FC19DC6),
    UInt32(0x240CA1CC),
    UInt32(0x2DE92C6F),
    UInt32(0x4A7484AA),
    UInt32(0x5CB0A9DC),
    UInt32(0x76F988DA),
    UInt32(0x983E5152),
    UInt32(0xA831C66D),
    UInt32(0xB00327C8),
    UInt32(0xBF597FC7),
    UInt32(0xC6E00BF3),
    UInt32(0xD5A79147),
    UInt32(0x06CA6351),
    UInt32(0x14292967),
    UInt32(0x27B70A85),
    UInt32(0x2E1B2138),
    UInt32(0x4D2C6DFC),
    UInt32(0x53380D13),
    UInt32(0x650A7354),
    UInt32(0x766A0ABB),
    UInt32(0x81C2C92E),
    UInt32(0x92722C85),
    UInt32(0xA2BFE8A1),
    UInt32(0xA81A664B),
    UInt32(0xC24B8B70),
    UInt32(0xC76C51A3),
    UInt32(0xD192E819),
    UInt32(0xD6990624),
    UInt32(0xF40E3585),
    UInt32(0x106AA070),
    UInt32(0x19A4C116),
    UInt32(0x1E376C08),
    UInt32(0x2748774C),
    UInt32(0x34B0BCB5),
    UInt32(0x391C0CB3),
    UInt32(0x4ED8AA4A),
    UInt32(0x5B9CCA4F),
    UInt32(0x682E6FF3),
    UInt32(0x748F82EE),
    UInt32(0x78A5636F),
    UInt32(0x84C87814),
    UInt32(0x8CC70208),
    UInt32(0x90BEFFFA),
    UInt32(0xA4506CEB),
    UInt32(0xBEF9A3F7),
    UInt32(0xC67178F2),
]


@always_inline
def _big_sigma_zero(value: UInt32) -> UInt32:
    return (
        rotate_bits_right[2](value)
        ^ rotate_bits_right[13](value)
        ^ rotate_bits_right[22](value)
    )


@always_inline
def _big_sigma_one(value: UInt32) -> UInt32:
    return (
        rotate_bits_right[6](value)
        ^ rotate_bits_right[11](value)
        ^ rotate_bits_right[25](value)
    )


@always_inline
def _small_sigma_zero(value: UInt32) -> UInt32:
    return (
        rotate_bits_right[7](value)
        ^ rotate_bits_right[18](value)
        ^ (value >> UInt32(3))
    )


@always_inline
def _small_sigma_one(value: UInt32) -> UInt32:
    return (
        rotate_bits_right[17](value)
        ^ rotate_bits_right[19](value)
        ^ (value >> UInt32(10))
    )


@always_inline
def _load_words(block: Span[Byte, _]) -> InlineArray[UInt32, 16]:
    var words = InlineArray[UInt32, 16](uninitialized=True)
    words.unsafe_ptr().unsafe_store(byte_swap(load_le_u32_words[16](block, 0)))
    return words^


struct _SHA256Core(Copyable, Movable):
    var _h: InlineArray[UInt32, 8]
    var _buffer: InlineArray[UInt8, 64]
    var _buffer_len: Int
    var _bit_length: UInt64

    def __init__(out self, var initial_h: InlineArray[UInt32, 8]):
        self._h = initial_h^
        self._buffer = InlineArray[UInt8, 64](fill=0)
        self._buffer_len = 0
        self._bit_length = 0

    @always_inline
    def _process_block(mut self, block: Span[Byte, _]):
        self._process_words(_load_words(block))

    @always_inline
    def _process_words(mut self, var words: InlineArray[UInt32, 16]):
        var a = self._h[0]
        var b = self._h[1]
        var c = self._h[2]
        var d = self._h[3]
        var e = self._h[4]
        var f = self._h[5]
        var g = self._h[6]
        var h = self._h[7]
        # The message schedule is a rolling 16-word window with compile-time
        # indices, so it stays in registers.
        comptime for i in range(64):
            comptime if i >= 16:
                words[i % 16] = (
                    _small_sigma_one(words[(i + 14) % 16])
                    + words[(i + 9) % 16]
                    + _small_sigma_zero(words[(i + 1) % 16])
                    + words[i % 16]
                )
            var choice = (e & f) ^ ((~e) & g)
            var majority = (a & b) ^ (a & c) ^ (b & c)
            var temp1 = (
                h
                + _big_sigma_one(e)
                + choice
                + materialize[_K[i]]()
                + words[i % 16]
            )
            var temp2 = _big_sigma_zero(a) + majority
            h = g
            g = f
            f = e
            e = d + temp1
            d = c
            c = b
            b = a
            a = temp1 + temp2

        self._h[0] += a
        self._h[1] += b
        self._h[2] += c
        self._h[3] += d
        self._h[4] += e
        self._h[5] += f
        self._h[6] += g
        self._h[7] += h

    def _process_buffer(mut self):
        var words = _load_words(Span(self._buffer))
        self._process_words(words^)
        self._buffer_len = 0

    def update_bytes(mut self, data: Span[Byte, _]):
        self._bit_length += UInt64(len(data)) * 8
        var offset = 0
        if self._buffer_len > 0:
            var needed = 64 - self._buffer_len
            var available = min(needed, len(data))
            copy_to_buffer(self._buffer, self._buffer_len, data, 0, available)
            self._buffer_len += available
            offset = available
            if self._buffer_len == 64:
                self._process_buffer()
        while offset + 64 <= len(data):
            self._process_block(data[offset : offset + 64])
            offset += 64
        var remaining = len(data) - offset
        copy_to_buffer(self._buffer, self._buffer_len, data, offset, remaining)
        self._buffer_len += remaining

    def _update_with_simd(mut self, value: SIMD[_, _]):
        var bytes = simd_lanes_be_u64(value)
        self.update_bytes(bytes[:])

    def _finalize(mut self):
        var original_length = self._bit_length
        self._buffer[self._buffer_len] = 0x80
        self._buffer_len += 1
        while self._buffer_len != 56:
            if self._buffer_len == 64:
                self._process_buffer()
            else:
                self._buffer[self._buffer_len] = 0
                self._buffer_len += 1
        write_be_u64(self._buffer, self._buffer_len, original_length)
        self._buffer_len += 8
        self._process_buffer()

    def digest(mut self) -> List[UInt8]:
        self._finalize()
        var output = List[UInt8](capacity=32)
        for i in range(8):
            append_be_u32(output, self._h[i])
        return output^

    def hexdigest(mut self) -> String:
        return bytes_to_hex(self.digest())

    def finish(mut self) -> UInt64:
        self._finalize()
        return (self._h[0].cast[DType.uint64]() << UInt64(32)) | self._h[
            1
        ].cast[DType.uint64]()


struct SHA256(Copyable, Defaultable, HashFunction, Hasher, Movable):
    comptime block_size = 64
    comptime digest_size = 32

    var _core: _SHA256Core

    def __init__(out self):
        self._core = _SHA256Core(
            [
                0x6A09E667,
                0xBB67AE85,
                0x3C6EF372,
                0xA54FF53A,
                0x510E527F,
                0x9B05688C,
                0x1F83D9AB,
                0x5BE0CD19,
            ]
        )

    def update_bytes(mut self, data: Span[Byte, _]):
        self._core.update_bytes(data)

    def _update_with_bytes(mut self, data: Span[Byte, _]):
        self._core.update_bytes(data)

    def _update_with_simd(mut self, value: SIMD[_, _]):
        self._core._update_with_simd(value)

    def update(mut self, value: Some[Hashable]):
        value.__hash__(self)

    def clone(self) -> Self:
        return self.copy()

    def reset(mut self):
        self._core = _SHA256Core(
            [
                0x6A09E667,
                0xBB67AE85,
                0x3C6EF372,
                0xA54FF53A,
                0x510E527F,
                0x9B05688C,
                0x1F83D9AB,
                0x5BE0CD19,
            ]
        )

    def digest(var self) -> List[UInt8]:
        return self._core.digest()

    def hexdigest(var self) -> String:
        return self._core.hexdigest()

    def finish(var self) -> UInt64:
        return self._core.finish()


struct SHA224(Copyable, Defaultable, HashFunction, Hasher, Movable):
    comptime block_size = 64
    comptime digest_size = 28

    var _core: _SHA256Core

    def __init__(out self):
        self._core = _SHA256Core(
            [
                0xC1059ED8,
                0x367CD507,
                0x3070DD17,
                0xF70E5939,
                0xFFC00B31,
                0x68581511,
                0x64F98FA7,
                0xBEFA4FA4,
            ]
        )

    def update_bytes(mut self, data: Span[Byte, _]):
        self._core.update_bytes(data)

    def _update_with_bytes(mut self, data: Span[Byte, _]):
        self._core.update_bytes(data)

    def _update_with_simd(mut self, value: SIMD[_, _]):
        self._core._update_with_simd(value)

    def update(mut self, value: Some[Hashable]):
        value.__hash__(self)

    def clone(self) -> Self:
        return self.copy()

    def reset(mut self):
        self._core = _SHA256Core(
            [
                0xC1059ED8,
                0x367CD507,
                0x3070DD17,
                0xF70E5939,
                0xFFC00B31,
                0x68581511,
                0x64F98FA7,
                0xBEFA4FA4,
            ]
        )

    def digest(var self) -> List[UInt8]:
        var full = self._core.digest()
        full.resize(28, 0)
        return full^

    def hexdigest(var self) -> String:
        return bytes_to_hex(self^.digest())

    def finish(var self) -> UInt64:
        return self._core.finish()
