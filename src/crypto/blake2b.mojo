from std.collections import List, Span
from std.hashlib.hasher import Hasher

from ._common import (
    append_le_u64,
    bytes_to_hex,
    read_le_u64,
    rotate_right_u64,
    simd_lanes_le_u64,
)


comptime _IV = [
    UInt64(0x6A09E667F3BCC908),
    UInt64(0xBB67AE8584CAA73B),
    UInt64(0x3C6EF372FE94F82B),
    UInt64(0xA54FF53A5F1D36F1),
    UInt64(0x510E527FADE682D1),
    UInt64(0x9B05688C2B3E6C1F),
    UInt64(0x1F83D9ABFB41BD6B),
    UInt64(0x5BE0CD19137E2179),
]

comptime _SIGMA = [
    [
        Int(0),
        Int(1),
        Int(2),
        Int(3),
        Int(4),
        Int(5),
        Int(6),
        Int(7),
        Int(8),
        Int(9),
        Int(10),
        Int(11),
        Int(12),
        Int(13),
        Int(14),
        Int(15),
    ],
    [
        Int(14),
        Int(10),
        Int(4),
        Int(8),
        Int(9),
        Int(15),
        Int(13),
        Int(6),
        Int(1),
        Int(12),
        Int(0),
        Int(2),
        Int(11),
        Int(7),
        Int(5),
        Int(3),
    ],
    [
        Int(11),
        Int(8),
        Int(12),
        Int(0),
        Int(5),
        Int(2),
        Int(15),
        Int(13),
        Int(10),
        Int(14),
        Int(3),
        Int(6),
        Int(7),
        Int(1),
        Int(9),
        Int(4),
    ],
    [
        Int(7),
        Int(9),
        Int(3),
        Int(1),
        Int(13),
        Int(12),
        Int(11),
        Int(14),
        Int(2),
        Int(6),
        Int(5),
        Int(10),
        Int(4),
        Int(0),
        Int(15),
        Int(8),
    ],
    [
        Int(9),
        Int(0),
        Int(5),
        Int(7),
        Int(2),
        Int(4),
        Int(10),
        Int(15),
        Int(14),
        Int(1),
        Int(11),
        Int(12),
        Int(6),
        Int(8),
        Int(3),
        Int(13),
    ],
    [
        Int(2),
        Int(12),
        Int(6),
        Int(10),
        Int(0),
        Int(11),
        Int(8),
        Int(3),
        Int(4),
        Int(13),
        Int(7),
        Int(5),
        Int(15),
        Int(14),
        Int(1),
        Int(9),
    ],
    [
        Int(12),
        Int(5),
        Int(1),
        Int(15),
        Int(14),
        Int(13),
        Int(4),
        Int(10),
        Int(0),
        Int(7),
        Int(6),
        Int(3),
        Int(9),
        Int(2),
        Int(8),
        Int(11),
    ],
    [
        Int(13),
        Int(11),
        Int(7),
        Int(14),
        Int(12),
        Int(1),
        Int(3),
        Int(9),
        Int(5),
        Int(0),
        Int(15),
        Int(4),
        Int(8),
        Int(6),
        Int(2),
        Int(10),
    ],
    [
        Int(6),
        Int(15),
        Int(14),
        Int(9),
        Int(11),
        Int(3),
        Int(0),
        Int(8),
        Int(12),
        Int(2),
        Int(13),
        Int(7),
        Int(1),
        Int(4),
        Int(10),
        Int(5),
    ],
    [
        Int(10),
        Int(2),
        Int(8),
        Int(4),
        Int(7),
        Int(6),
        Int(1),
        Int(5),
        Int(15),
        Int(11),
        Int(9),
        Int(14),
        Int(3),
        Int(12),
        Int(13),
        Int(0),
    ],
]


def _g(
    mut v: InlineArray[UInt64, 16],
    a: Int,
    b: Int,
    c: Int,
    d: Int,
    x: UInt64,
    y: UInt64,
):
    v[a] = v[a] + v[b] + x
    v[d] = rotate_right_u64(v[d] ^ v[a], 32)
    v[c] = v[c] + v[d]
    v[b] = rotate_right_u64(v[b] ^ v[c], 24)
    v[a] = v[a] + v[b] + y
    v[d] = rotate_right_u64(v[d] ^ v[a], 16)
    v[c] = v[c] + v[d]
    v[b] = rotate_right_u64(v[b] ^ v[c], 63)


def _block_words(block: Span[Byte, _]) -> InlineArray[UInt64, 16]:
    var words = InlineArray[UInt64, 16](uninitialized=True)
    for i in range(16):
        words[i] = read_le_u64(block, i * 8)
    return words^


struct _BLAKE2bCore:
    var _h: InlineArray[UInt64, 8]
    var _buffer: InlineArray[UInt8, 128]
    var _buffer_len: Int
    var _t0: UInt64
    var _t1: UInt64
    var _f0: UInt64
    var _digest_size: Int

    def __init__(out self, digest_size: Int = 64):
        self._h = InlineArray[UInt64, 8](uninitialized=True)
        var parameter = (
            UInt64(digest_size)
            | (UInt64(1) << UInt64(16))
            | (UInt64(1) << UInt64(24))
        )
        comptime for i in range(8):
            self._h[i] = materialize[_IV[i]]()
        self._h[0] ^= parameter
        self._buffer = InlineArray[UInt8, 128](fill=0)
        self._buffer_len = 0
        self._t0 = 0
        self._t1 = 0
        self._f0 = 0
        self._digest_size = digest_size

    def _increment_counter(mut self, amount: UInt64):
        var previous = self._t0
        self._t0 += amount
        if self._t0 < previous:
            self._t1 += 1

    def _compress(mut self, block: Span[Byte, _]):
        self._compress_words(_block_words(block))

    def _compress_words(mut self, m: InlineArray[UInt64, 16]):
        var v = InlineArray[UInt64, 16](uninitialized=True)
        comptime for i in range(8):
            v[i] = self._h[i]
            v[i + 8] = materialize[_IV[i]]()
        v[12] ^= self._t0
        v[13] ^= self._t1
        v[14] ^= self._f0

        comptime for round in range(12):
            _g(
                v,
                0,
                4,
                8,
                12,
                m[materialize[_SIGMA[round % 10][0]]()],
                m[materialize[_SIGMA[round % 10][1]]()],
            )
            _g(
                v,
                1,
                5,
                9,
                13,
                m[materialize[_SIGMA[round % 10][2]]()],
                m[materialize[_SIGMA[round % 10][3]]()],
            )
            _g(
                v,
                2,
                6,
                10,
                14,
                m[materialize[_SIGMA[round % 10][4]]()],
                m[materialize[_SIGMA[round % 10][5]]()],
            )
            _g(
                v,
                3,
                7,
                11,
                15,
                m[materialize[_SIGMA[round % 10][6]]()],
                m[materialize[_SIGMA[round % 10][7]]()],
            )
            _g(
                v,
                0,
                5,
                10,
                15,
                m[materialize[_SIGMA[round % 10][8]]()],
                m[materialize[_SIGMA[round % 10][9]]()],
            )
            _g(
                v,
                1,
                6,
                11,
                12,
                m[materialize[_SIGMA[round % 10][10]]()],
                m[materialize[_SIGMA[round % 10][11]]()],
            )
            _g(
                v,
                2,
                7,
                8,
                13,
                m[materialize[_SIGMA[round % 10][12]]()],
                m[materialize[_SIGMA[round % 10][13]]()],
            )
            _g(
                v,
                3,
                4,
                9,
                14,
                m[materialize[_SIGMA[round % 10][14]]()],
                m[materialize[_SIGMA[round % 10][15]]()],
            )

        for i in range(8):
            self._h[i] ^= v[i] ^ v[i + 8]

    def _process_buffer(mut self):
        var words = _block_words(Span(self._buffer))
        self._compress_words(words)
        self._buffer_len = 0

    def update_bytes(mut self, data: Span[Byte, _]):
        var offset = 0
        if self._buffer_len > 0:
            var needed = 128 - self._buffer_len
            var available = min(needed, len(data))
            for i in range(available):
                self._buffer[self._buffer_len + i] = data[i]
            self._buffer_len += available
            offset = available
            if self._buffer_len == 128 and offset < len(data):
                self._increment_counter(UInt64(128))
                self._process_buffer()
        while offset + 128 < len(data):
            self._increment_counter(UInt64(128))
            self._compress(data[offset : offset + 128])
            offset += 128
        for i in range(offset, len(data)):
            self._buffer[self._buffer_len] = data[i]
            self._buffer_len += 1

    def _update_with_simd(mut self, value: SIMD[_, _]):
        var bytes = simd_lanes_le_u64(value)
        self.update_bytes(bytes[:])

    def _finalize(mut self):
        self._f0 = 0xFFFFFFFFFFFFFFFF
        self._increment_counter(UInt64(self._buffer_len))
        while self._buffer_len < 128:
            self._buffer[self._buffer_len] = 0
            self._buffer_len += 1
        self._process_buffer()

    def digest(mut self) -> List[UInt8]:
        self._finalize()
        var full = List[UInt8](capacity=64)
        for i in range(8):
            append_le_u64(full, self._h[i])
        var output = List[UInt8](capacity=self._digest_size)
        for i in range(self._digest_size):
            output.append(full[i])
        return output^

    def hexdigest(mut self) -> String:
        return bytes_to_hex(self.digest())

    def finish(mut self) -> UInt64:
        self._finalize()
        return self._h[0]


struct BLAKE2b(Defaultable, Hasher):
    var _core: _BLAKE2bCore

    def __init__(out self):
        self._core = _BLAKE2bCore(64)

    def __init__(out self, digest_size: Int):
        self._core = _BLAKE2bCore(digest_size)

    def update_bytes(mut self, data: Span[Byte, _]):
        self._core.update_bytes(data)

    def _update_with_bytes(mut self, data: Span[Byte, _]):
        self._core.update_bytes(data)

    def _update_with_simd(mut self, value: SIMD[_, _]):
        self._core._update_with_simd(value)

    def update(mut self, value: Some[Hashable]):
        value.__hash__(self)

    def digest(var self) -> List[UInt8]:
        return self._core.digest()

    def hexdigest(var self) -> String:
        return self._core.hexdigest()

    def finish(var self) -> UInt64:
        return self._core.finish()
