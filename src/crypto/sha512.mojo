from std.bit import rotate_bits_right
from std.collections import List, Span
from std.hashlib.hasher import Hasher

from ._common import (
    HashFunction,
    append_be_u64,
    bytes_to_hex,
    read_be_u64,
    simd_lanes_be_u64,
    write_be_u64,
)


comptime _K = [
    UInt64(0x428A2F98D728AE22),
    UInt64(0x7137449123EF65CD),
    UInt64(0xB5C0FBCFEC4D3B2F),
    UInt64(0xE9B5DBA58189DBBC),
    UInt64(0x3956C25BF348B538),
    UInt64(0x59F111F1B605D019),
    UInt64(0x923F82A4AF194F9B),
    UInt64(0xAB1C5ED5DA6D8118),
    UInt64(0xD807AA98A3030242),
    UInt64(0x12835B0145706FBE),
    UInt64(0x243185BE4EE4B28C),
    UInt64(0x550C7DC3D5FFB4E2),
    UInt64(0x72BE5D74F27B896F),
    UInt64(0x80DEB1FE3B1696B1),
    UInt64(0x9BDC06A725C71235),
    UInt64(0xC19BF174CF692694),
    UInt64(0xE49B69C19EF14AD2),
    UInt64(0xEFBE4786384F25E3),
    UInt64(0x0FC19DC68B8CD5B5),
    UInt64(0x240CA1CC77AC9C65),
    UInt64(0x2DE92C6F592B0275),
    UInt64(0x4A7484AA6EA6E483),
    UInt64(0x5CB0A9DCBD41FBD4),
    UInt64(0x76F988DA831153B5),
    UInt64(0x983E5152EE66DFAB),
    UInt64(0xA831C66D2DB43210),
    UInt64(0xB00327C898FB213F),
    UInt64(0xBF597FC7BEEF0EE4),
    UInt64(0xC6E00BF33DA88FC2),
    UInt64(0xD5A79147930AA725),
    UInt64(0x06CA6351E003826F),
    UInt64(0x142929670A0E6E70),
    UInt64(0x27B70A8546D22FFC),
    UInt64(0x2E1B21385C26C926),
    UInt64(0x4D2C6DFC5AC42AED),
    UInt64(0x53380D139D95B3DF),
    UInt64(0x650A73548BAF63DE),
    UInt64(0x766A0ABB3C77B2A8),
    UInt64(0x81C2C92E47EDAEE6),
    UInt64(0x92722C851482353B),
    UInt64(0xA2BFE8A14CF10364),
    UInt64(0xA81A664BBC423001),
    UInt64(0xC24B8B70D0F89791),
    UInt64(0xC76C51A30654BE30),
    UInt64(0xD192E819D6EF5218),
    UInt64(0xD69906245565A910),
    UInt64(0xF40E35855771202A),
    UInt64(0x106AA07032BBD1B8),
    UInt64(0x19A4C116B8D2D0C8),
    UInt64(0x1E376C085141AB53),
    UInt64(0x2748774CDF8EEB99),
    UInt64(0x34B0BCB5E19B48A8),
    UInt64(0x391C0CB3C5C95A63),
    UInt64(0x4ED8AA4AE3418ACB),
    UInt64(0x5B9CCA4F7763E373),
    UInt64(0x682E6FF3D6B2B8A3),
    UInt64(0x748F82EE5DEFB2FC),
    UInt64(0x78A5636F43172F60),
    UInt64(0x84C87814A1F0AB72),
    UInt64(0x8CC702081A6439EC),
    UInt64(0x90BEFFFA23631E28),
    UInt64(0xA4506CEBDE82BDE9),
    UInt64(0xBEF9A3F7B2C67915),
    UInt64(0xC67178F2E372532B),
    UInt64(0xCA273ECEEA26619C),
    UInt64(0xD186B8C721C0C207),
    UInt64(0xEADA7DD6CDE0EB1E),
    UInt64(0xF57D4F7FEE6ED178),
    UInt64(0x06F067AA72176FBA),
    UInt64(0x0A637DC5A2C898A6),
    UInt64(0x113F9804BEF90DAE),
    UInt64(0x1B710B35131C471B),
    UInt64(0x28DB77F523047D84),
    UInt64(0x32CAAB7B40C72493),
    UInt64(0x3C9EBE0A15C9BEBC),
    UInt64(0x431D67C49C100D4C),
    UInt64(0x4CC5D4BECB3E42B6),
    UInt64(0x597F299CFC657E2A),
    UInt64(0x5FCB6FAB3AD6FAEC),
    UInt64(0x6C44198C4A475817),
]


def _big_sigma_zero(value: UInt64) -> UInt64:
    return (
        rotate_bits_right[28](value)
        ^ rotate_bits_right[34](value)
        ^ rotate_bits_right[39](value)
    )


def _big_sigma_one(value: UInt64) -> UInt64:
    return (
        rotate_bits_right[14](value)
        ^ rotate_bits_right[18](value)
        ^ rotate_bits_right[41](value)
    )


def _small_sigma_zero(value: UInt64) -> UInt64:
    return (
        rotate_bits_right[1](value)
        ^ rotate_bits_right[8](value)
        ^ (value >> UInt64(7))
    )


def _small_sigma_one(value: UInt64) -> UInt64:
    return (
        rotate_bits_right[19](value)
        ^ rotate_bits_right[61](value)
        ^ (value >> UInt64(6))
    )


def _message_schedule(block: Span[Byte, _]) -> InlineArray[UInt64, 80]:
    var words = InlineArray[UInt64, 80](uninitialized=True)
    for i in range(16):
        words[i] = read_be_u64(block, i * 8)
    for i in range(16, 80):
        var word = _small_sigma_one(words[i - 2]) + words[i - 7]
        word += _small_sigma_zero(words[i - 15]) + words[i - 16]
        words[i] = word
    return words^


struct _SHA512Core(Copyable, Movable):
    var _h: InlineArray[UInt64, 8]
    var _buffer: InlineArray[UInt8, 128]
    var _buffer_len: Int
    var _bit_length_high: UInt64
    var _bit_length_low: UInt64

    def __init__(out self, var initial_h: InlineArray[UInt64, 8]):
        self._h = initial_h^
        self._buffer = InlineArray[UInt8, 128](fill=0)
        self._buffer_len = 0
        self._bit_length_high = 0
        self._bit_length_low = 0

    def _process_block(mut self, block: Span[Byte, _]):
        self._process_words(_message_schedule(block))

    def _process_words(mut self, words: InlineArray[UInt64, 80]):
        var a = self._h[0]
        var b = self._h[1]
        var c = self._h[2]
        var d = self._h[3]
        var e = self._h[4]
        var f = self._h[5]
        var g = self._h[6]
        var h = self._h[7]
        comptime for i in range(80):
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

        self._h[0] += a
        self._h[1] += b
        self._h[2] += c
        self._h[3] += d
        self._h[4] += e
        self._h[5] += f
        self._h[6] += g
        self._h[7] += h

    def _process_buffer(mut self):
        var words = _message_schedule(Span(self._buffer))
        self._process_words(words)
        self._buffer_len = 0

    def update_bytes(mut self, data: Span[Byte, _]):
        var byte_length = UInt64(len(data))
        var low_increment = byte_length << UInt64(3)
        var high_increment = byte_length >> UInt64(61)
        var previous_low = self._bit_length_low
        self._bit_length_low += low_increment
        if self._bit_length_low < previous_low:
            high_increment += 1
        self._bit_length_high += high_increment

        var offset = 0
        if self._buffer_len > 0:
            var needed = 128 - self._buffer_len
            var available = min(needed, len(data))
            for i in range(available):
                self._buffer[self._buffer_len + i] = data[i]
            self._buffer_len += available
            offset = available
            if self._buffer_len == 128:
                self._process_buffer()
        while offset + 128 <= len(data):
            self._process_block(data[offset : offset + 128])
            offset += 128
        for i in range(offset, len(data)):
            self._buffer[self._buffer_len] = data[i]
            self._buffer_len += 1

    def _update_with_simd(mut self, value: SIMD[_, _]):
        var bytes = simd_lanes_be_u64(value)
        self.update_bytes(bytes[:])

    def _finalize(mut self):
        var original_length_high = self._bit_length_high
        var original_length_low = self._bit_length_low
        self._buffer[self._buffer_len] = 0x80
        self._buffer_len += 1
        while self._buffer_len != 112:
            if self._buffer_len == 128:
                self._process_buffer()
            else:
                self._buffer[self._buffer_len] = 0
                self._buffer_len += 1
        write_be_u64(self._buffer, self._buffer_len, original_length_high)
        write_be_u64(self._buffer, self._buffer_len + 8, original_length_low)
        self._buffer_len += 16
        self._process_buffer()

    def digest(mut self) -> List[UInt8]:
        self._finalize()
        var output = List[UInt8](capacity=64)
        for i in range(8):
            append_be_u64(output, self._h[i])
        return output^

    def hexdigest(mut self) -> String:
        return bytes_to_hex(self.digest())

    def finish(mut self) -> UInt64:
        self._finalize()
        return self._h[0]


struct SHA512(Copyable, Defaultable, HashFunction, Hasher, Movable):
    comptime block_size = 128
    comptime digest_size = 64

    var _core: _SHA512Core

    def __init__(out self):
        self._core = _SHA512Core(
            [
                0x6A09E667F3BCC908,
                0xBB67AE8584CAA73B,
                0x3C6EF372FE94F82B,
                0xA54FF53A5F1D36F1,
                0x510E527FADE682D1,
                0x9B05688C2B3E6C1F,
                0x1F83D9ABFB41BD6B,
                0x5BE0CD19137E2179,
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
        self._core = _SHA512Core(
            [
                0x6A09E667F3BCC908,
                0xBB67AE8584CAA73B,
                0x3C6EF372FE94F82B,
                0xA54FF53A5F1D36F1,
                0x510E527FADE682D1,
                0x9B05688C2B3E6C1F,
                0x1F83D9ABFB41BD6B,
                0x5BE0CD19137E2179,
            ]
        )

    def digest(var self) -> List[UInt8]:
        return self._core.digest()

    def hexdigest(var self) -> String:
        return self._core.hexdigest()

    def finish(var self) -> UInt64:
        return self._core.finish()


struct SHA384(Copyable, Defaultable, HashFunction, Hasher, Movable):
    comptime block_size = 128
    comptime digest_size = 48

    var _core: _SHA512Core

    def __init__(out self):
        self._core = _SHA512Core(
            [
                0xCBBB9D5DC1059ED8,
                0x629A292A367CD507,
                0x9159015A3070DD17,
                0x152FECD8F70E5939,
                0x67332667FFC00B31,
                0x8EB44A8768581511,
                0xDB0C2E0D64F98FA7,
                0x47B5481DBEFA4FA4,
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
        self._core = _SHA512Core(
            [
                0xCBBB9D5DC1059ED8,
                0x629A292A367CD507,
                0x9159015A3070DD17,
                0x152FECD8F70E5939,
                0x67332667FFC00B31,
                0x8EB44A8768581511,
                0xDB0C2E0D64F98FA7,
                0x47B5481DBEFA4FA4,
            ]
        )

    def digest(var self) -> List[UInt8]:
        var full = self._core.digest()
        full.resize(48, 0)
        return full^

    def hexdigest(var self) -> String:
        return bytes_to_hex(self^.digest())

    def finish(var self) -> UInt64:
        return self._core.finish()
