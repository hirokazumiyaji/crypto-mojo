from std.bit import rotate_bits_left
from std.collections import List, Span
from std.hashlib.hasher import Hasher

from ._common import (
    append_le_u32,
    bytes_to_hex,
    copy_to_buffer,
    load_le_u32_words,
    simd_lanes_le_u64,
    write_le_u64,
)


comptime _SHIFT = [
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
]

comptime _K = [
    UInt32(0xD76AA478),
    UInt32(0xE8C7B756),
    UInt32(0x242070DB),
    UInt32(0xC1BDCEEE),
    UInt32(0xF57C0FAF),
    UInt32(0x4787C62A),
    UInt32(0xA8304613),
    UInt32(0xFD469501),
    UInt32(0x698098D8),
    UInt32(0x8B44F7AF),
    UInt32(0xFFFF5BB1),
    UInt32(0x895CD7BE),
    UInt32(0x6B901122),
    UInt32(0xFD987193),
    UInt32(0xA679438E),
    UInt32(0x49B40821),
    UInt32(0xF61E2562),
    UInt32(0xC040B340),
    UInt32(0x265E5A51),
    UInt32(0xE9B6C7AA),
    UInt32(0xD62F105D),
    UInt32(0x02441453),
    UInt32(0xD8A1E681),
    UInt32(0xE7D3FBC8),
    UInt32(0x21E1CDE6),
    UInt32(0xC33707D6),
    UInt32(0xF4D50D87),
    UInt32(0x455A14ED),
    UInt32(0xA9E3E905),
    UInt32(0xFCEFA3F8),
    UInt32(0x676F02D9),
    UInt32(0x8D2A4C8A),
    UInt32(0xFFFA3942),
    UInt32(0x8771F681),
    UInt32(0x6D9D6122),
    UInt32(0xFDE5380C),
    UInt32(0xA4BEEA44),
    UInt32(0x4BDECFA9),
    UInt32(0xF6BB4B60),
    UInt32(0xBEBFBC70),
    UInt32(0x289B7EC6),
    UInt32(0xEAA127FA),
    UInt32(0xD4EF3085),
    UInt32(0x04881D05),
    UInt32(0xD9D4D039),
    UInt32(0xE6DB99E5),
    UInt32(0x1FA27CF8),
    UInt32(0xC4AC5665),
    UInt32(0xF4292244),
    UInt32(0x432AFF97),
    UInt32(0xAB9423A7),
    UInt32(0xFC93A039),
    UInt32(0x655B59C3),
    UInt32(0x8F0CCC92),
    UInt32(0xFFEFF47D),
    UInt32(0x85845DD1),
    UInt32(0x6FA87E4F),
    UInt32(0xFE2CE6E0),
    UInt32(0xA3014314),
    UInt32(0x4E0811A1),
    UInt32(0xF7537E82),
    UInt32(0xBD3AF235),
    UInt32(0x2AD7D2BB),
    UInt32(0xEB86D391),
]


@always_inline
def _block_words(block: Span[Byte, _]) -> Array[UInt32, 16]:
    var words = Array[UInt32, 16](uninitialized=True)
    words.unsafe_ptr().unsafe_store(load_le_u32_words[16](block, 0))
    return words^


struct MD5(Copyable, Defaultable, Hasher, Movable):
    var _state: Array[UInt32, 4]
    var _buffer: Array[UInt8, 64]
    var _buffer_len: Int
    var _bit_length: UInt64

    def __init__(out self):
        self._state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        self._buffer = Array[UInt8, 64](fill=0)
        self._buffer_len = 0
        self._bit_length = 0

    @always_inline
    def _process_block(mut self, block: Span[Byte, _]):
        self._process_words(_block_words(block))

    @always_inline
    def _process_words(mut self, words: Array[UInt32, 16]):
        var a = self._state[0]
        var b = self._state[1]
        var c = self._state[2]
        var d = self._state[3]
        comptime for i in range(64):
            var f: UInt32
            var g: Int
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16
            var value = a + f + materialize[_K[i]]() + words[g]
            a = d
            d = c
            c = b
            b = b + rotate_bits_left[_SHIFT[i]](value)

        self._state[0] += a
        self._state[1] += b
        self._state[2] += c
        self._state[3] += d

    def _process_buffer(mut self):
        var words = _block_words(Span(self._buffer))
        self._process_words(words)
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
        var bytes = simd_lanes_le_u64(value)
        self.update_bytes(bytes[:])

    def update(mut self, value: ImmSpan[Byte, _]):
        self.update_bytes(value)

    def clone(self) -> Self:
        return self.copy()

    def reset(mut self):
        self._state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        self._buffer = Array[UInt8, 64](fill=0)
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
        write_le_u64(self._buffer, self._buffer_len, original_length)
        self._buffer_len += 8
        self._process_buffer()

    def digest(var self) -> List[UInt8]:
        self._finalize()
        var output = List[UInt8](capacity=16)
        for i in range(4):
            append_le_u32(output, self._state[i])
        return output^

    def hexdigest(var self) -> String:
        return bytes_to_hex(self^.digest())

    def finish(var self) -> UInt64:
        self._finalize()
        return self._state[0].cast[DType.uint64]() | (
            self._state[1].cast[DType.uint64]() << UInt64(32)
        )
