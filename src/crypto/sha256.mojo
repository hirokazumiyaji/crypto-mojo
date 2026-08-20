from std.collections import List, Span
from std.hashlib.hasher import Hasher

from ._common import (
    append_be_u32,
    bytes_to_hex,
    read_be_u32,
    rotate_right_u32,
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


def _big_sigma_zero(value: UInt32) -> UInt32:
    return (
        rotate_right_u32(value, 2)
        ^ rotate_right_u32(value, 13)
        ^ rotate_right_u32(value, 22)
    )


def _big_sigma_one(value: UInt32) -> UInt32:
    return (
        rotate_right_u32(value, 6)
        ^ rotate_right_u32(value, 11)
        ^ rotate_right_u32(value, 25)
    )


def _small_sigma_zero(value: UInt32) -> UInt32:
    return (
        rotate_right_u32(value, 7)
        ^ rotate_right_u32(value, 18)
        ^ (value >> UInt32(3))
    )


def _small_sigma_one(value: UInt32) -> UInt32:
    return (
        rotate_right_u32(value, 17)
        ^ rotate_right_u32(value, 19)
        ^ (value >> UInt32(10))
    )


def _message_schedule(block: Span[Byte, _]) -> InlineArray[UInt32, 64]:
    var words = InlineArray[UInt32, 64](uninitialized=True)
    for i in range(16):
        words[i] = read_be_u32(block, i * 4)
    for i in range(16, 64):
        var word = _small_sigma_one(words[i - 2]) + words[i - 7]
        word += _small_sigma_zero(words[i - 15]) + words[i - 16]
        words[i] = word
    return words^


struct SHA256(Defaultable, Hasher):
    var _h0: UInt32
    var _h1: UInt32
    var _h2: UInt32
    var _h3: UInt32
    var _h4: UInt32
    var _h5: UInt32
    var _h6: UInt32
    var _h7: UInt32
    var _buffer: InlineArray[UInt8, 64]
    var _buffer_len: Int
    var _bit_length: UInt64

    def __init__(out self):
        self._h0 = 0x6A09E667
        self._h1 = 0xBB67AE85
        self._h2 = 0x3C6EF372
        self._h3 = 0xA54FF53A
        self._h4 = 0x510E527F
        self._h5 = 0x9B05688C
        self._h6 = 0x1F83D9AB
        self._h7 = 0x5BE0CD19
        self._buffer = InlineArray[UInt8, 64](fill=0)
        self._buffer_len = 0
        self._bit_length = 0

    def _process_block(mut self, block: Span[Byte, _]):
        self._process_words(_message_schedule(block))

    def _process_words(mut self, words: InlineArray[UInt32, 64]):
        var a = self._h0
        var b = self._h1
        var c = self._h2
        var d = self._h3
        var e = self._h4
        var f = self._h5
        var g = self._h6
        var h = self._h7
        comptime for i in range(64):
            var choice = (e & f) ^ ((~e) & g)
            var majority = (a & b) ^ (a & c) ^ (b & c)
            var temp1 = (
                h + _big_sigma_one(e) + choice + materialize[_K[i]]() + words[i]
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

        self._h0 += a
        self._h1 += b
        self._h2 += c
        self._h3 += d
        self._h4 += e
        self._h5 += f
        self._h6 += g
        self._h7 += h

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
        var output = List[UInt8](capacity=32)
        append_be_u32(output, self._h0)
        append_be_u32(output, self._h1)
        append_be_u32(output, self._h2)
        append_be_u32(output, self._h3)
        append_be_u32(output, self._h4)
        append_be_u32(output, self._h5)
        append_be_u32(output, self._h6)
        append_be_u32(output, self._h7)
        return output^

    def hexdigest(var self) -> String:
        return bytes_to_hex(self^.digest())

    def finish(var self) -> UInt64:
        self._finalize()
        return (self._h0.cast[DType.uint64]() << UInt64(32)) | self._h1.cast[
            DType.uint64
        ]()
