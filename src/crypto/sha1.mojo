from std.bit import byte_swap, rotate_bits_left
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


@always_inline
def _load_words(block: Span[Byte, _]) -> InlineArray[UInt32, 16]:
    var words = InlineArray[UInt32, 16](uninitialized=True)
    words.unsafe_ptr().unsafe_store(byte_swap(load_le_u32_words[16](block, 0)))
    return words^


struct SHA1(Copyable, Defaultable, HashFunction, Hasher, Movable):
    comptime block_size = 64
    comptime digest_size = 20

    var _h: InlineArray[UInt32, 5]
    var _buffer: InlineArray[UInt8, 64]
    var _buffer_len: Int
    var _bit_length: UInt64

    def __init__(out self):
        self._h = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        ]
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
        # The message schedule is a rolling 16-word window with compile-time
        # indices, so it stays in registers.
        comptime for i in range(80):
            comptime if i >= 16:
                words[i % 16] = rotate_bits_left[1](
                    words[(i + 13) % 16]
                    ^ words[(i + 8) % 16]
                    ^ words[(i + 2) % 16]
                    ^ words[i % 16]
                )
            var f: UInt32
            var k: UInt32
            if i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            var temp = rotate_bits_left[5](a) + f + e + k + words[i % 16]
            e = d
            d = c
            c = rotate_bits_left[30](b)
            b = a
            a = temp

        self._h[0] += a
        self._h[1] += b
        self._h[2] += c
        self._h[3] += d
        self._h[4] += e

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

    def _update_with_bytes(mut self, data: Span[Byte, _]):
        self.update_bytes(data)

    def _update_with_simd(mut self, value: SIMD[_, _]):
        var bytes = simd_lanes_be_u64(value)
        self.update_bytes(bytes[:])

    def update(mut self, value: Some[Hashable]):
        value.__hash__(self)

    def clone(self) -> Self:
        return self.copy()

    def reset(mut self):
        self._h = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        ]
        self._buffer = InlineArray[UInt8, 64](fill=0)
        self._buffer_len = 0
        self._bit_length = 0

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

    def digest(var self) -> List[UInt8]:
        self._finalize()
        var output = List[UInt8](capacity=20)
        for i in range(5):
            append_be_u32(output, self._h[i])
        return output^

    def hexdigest(var self) -> String:
        return bytes_to_hex(self^.digest())

    def finish(var self) -> UInt64:
        self._finalize()
        return (self._h[0].cast[DType.uint64]() << UInt64(32)) | self._h[
            1
        ].cast[DType.uint64]()
