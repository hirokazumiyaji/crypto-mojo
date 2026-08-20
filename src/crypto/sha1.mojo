from std.bit import rotate_bits_left
from std.collections import List, Span
from std.hashlib.hasher import Hasher

from ._common import (
    HashFunction,
    append_be_u32,
    bytes_to_hex,
    read_be_u32,
    simd_lanes_be_u64,
    write_be_u64,
)


def _message_schedule(block: Span[Byte, _]) -> InlineArray[UInt32, 80]:
    var words = InlineArray[UInt32, 80](uninitialized=True)
    for i in range(16):
        words[i] = read_be_u32(block, i * 4)
    for i in range(16, 80):
        words[i] = rotate_bits_left[1](
            words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]
        )
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

    def _process_block(mut self, block: Span[Byte, _]):
        self._process_words(_message_schedule(block))

    def _process_words(mut self, words: InlineArray[UInt32, 80]):
        var a = self._h[0]
        var b = self._h[1]
        var c = self._h[2]
        var d = self._h[3]
        var e = self._h[4]
        comptime for i in range(80):
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
            var temp = rotate_bits_left[5](a) + f + e + k + words[i]
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
        var words = _message_schedule(Span(self._buffer))
        self._process_words(words)
        self._buffer_len = 0

    def update_bytes(mut self, data: Span[Byte, _]):
        self._bit_length += UInt64(len(data)) * 8
        var offset = 0
        if self._buffer_len > 0:
            var needed = 64 - self._buffer_len
            var available = min(needed, len(data))
            for i in range(available):
                self._buffer[self._buffer_len + i] = data[i]
            self._buffer_len += available
            offset = available
            if self._buffer_len == 64:
                self._process_buffer()
        while offset + 64 <= len(data):
            self._process_block(data[offset : offset + 64])
            offset += 64
        for i in range(offset, len(data)):
            self._buffer[self._buffer_len] = data[i]
            self._buffer_len += 1

    def _update_with_bytes(mut self, data: Span[Byte, _]):
        self.update_bytes(data)

    def _update_with_simd(mut self, value: SIMD[_, _]):
        var bytes = simd_lanes_be_u64(value)
        self.update_bytes(bytes[:])

    def update(mut self, value: Some[Hashable]):
        value.__hash__(self)

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
