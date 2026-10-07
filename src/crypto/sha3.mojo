from std.bit import rotate_bits_left
from std.collections import List, Span
from std.hashlib.hasher import Hasher

from ._common import (
    HashFunction,
    append_le_u64,
    bytes_to_hex,
    copy_to_buffer,
    load_le_u64_words,
    read_le_u64,
    simd_lanes_le_u64,
)


comptime _ROUND_CONSTANTS = [
    UInt64(0x0000000000000001),
    UInt64(0x0000000000008082),
    UInt64(0x800000000000808A),
    UInt64(0x8000000080008000),
    UInt64(0x000000000000808B),
    UInt64(0x0000000080000001),
    UInt64(0x8000000080008081),
    UInt64(0x8000000000008009),
    UInt64(0x000000000000008A),
    UInt64(0x0000000000000088),
    UInt64(0x0000000080008009),
    UInt64(0x000000008000000A),
    UInt64(0x000000008000808B),
    UInt64(0x800000000000008B),
    UInt64(0x8000000000008089),
    UInt64(0x8000000000008003),
    UInt64(0x8000000000008002),
    UInt64(0x8000000000000080),
    UInt64(0x000000000000800A),
    UInt64(0x800000008000000A),
    UInt64(0x8000000080008081),
    UInt64(0x8000000000008080),
    UInt64(0x0000000080000001),
    UInt64(0x8000000080008008),
]

# Indexed as [y][x], matching the state layout state[x + 5 * y].
comptime _ROTATION_OFFSETS: List[List[Int]] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
]


@always_inline
def _block_lanes(block: Span[Byte, _]) -> Array[UInt64, 17]:
    var lanes = Array[UInt64, 17](uninitialized=True)
    lanes.unsafe_ptr().unsafe_store(load_le_u64_words[16](block, 0))
    lanes[16] = read_le_u64(block, 128)
    return lanes^


struct SHA3_256(Copyable, Defaultable, HashFunction, Hasher, Movable):
    comptime block_size = 136
    comptime digest_size = 32

    var _state: Array[UInt64, 25]
    var _buffer: Array[UInt8, 136]
    var _buffer_len: Int

    def __init__(out self):
        self._state = Array[UInt64, 25](fill=0)
        self._buffer = Array[UInt8, 136](fill=0)
        self._buffer_len = 0

    def _permute(mut self):
        # Work on a local copy so the state lives in registers instead of
        # going through `self` on every access.
        var state = self._state.copy()
        var c = Array[UInt64, 5](uninitialized=True)
        var d = Array[UInt64, 5](uninitialized=True)
        var b = Array[UInt64, 5 * 5](uninitialized=True)
        comptime for round in range(24):
            comptime for x in range(5):
                c[x] = (
                    state[x]
                    ^ state[x + 5]
                    ^ state[x + 10]
                    ^ state[x + 15]
                    ^ state[x + 20]
                )
            comptime for x in range(5):
                d[x] = c[(x + 4) % 5] ^ rotate_bits_left[1](c[(x + 1) % 5])
            comptime for y in range(5):
                comptime for x in range(5):
                    state[x + 5 * y] ^= d[x]
            comptime for y in range(5):
                comptime for x in range(5):
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = rotate_bits_left[
                        _ROTATION_OFFSETS[y][x]
                    ](state[x + 5 * y])
            comptime for y in range(5):
                comptime for x in range(5):
                    state[x + 5 * y] = b[x + 5 * y] ^ (
                        (~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]
                    )
            state[0] ^= materialize[_ROUND_CONSTANTS[round]]()
        self._state = state^

    @always_inline
    def _absorb(mut self, lanes: Array[UInt64, 17]):
        for i in range(17):
            self._state[i] ^= lanes[i]
        self._permute()

    def _process_buffer(mut self):
        var lanes = _block_lanes(Span(self._buffer))
        self._absorb(lanes)
        self._buffer_len = 0

    def update_bytes(mut self, data: Span[Byte, _]):
        var offset = 0
        if self._buffer_len > 0:
            var needed = 136 - self._buffer_len
            var available = min(needed, len(data))
            copy_to_buffer(self._buffer, self._buffer_len, data, 0, available)
            self._buffer_len += available
            offset = available
            if self._buffer_len == 136:
                self._process_buffer()
        while offset + 136 <= len(data):
            self._absorb(_block_lanes(data[offset : offset + 136]))
            offset += 136
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
        self._state = Array[UInt64, 25](fill=0)
        self._buffer = Array[UInt8, 136](fill=0)
        self._buffer_len = 0

    def _finalize(mut self):
        self._buffer[self._buffer_len] = 0x06
        self._buffer_len += 1
        while self._buffer_len < 136:
            self._buffer[self._buffer_len] = 0
            self._buffer_len += 1
        self._buffer[135] |= 0x80
        self._process_buffer()

    def digest(var self) -> List[UInt8]:
        self._finalize()
        var output = List[UInt8](capacity=32)
        for i in range(4):
            append_le_u64(output, self._state[i])
        return output^

    def hexdigest(var self) -> String:
        return bytes_to_hex(self^.digest())

    def finish(var self) -> UInt64:
        self._finalize()
        return self._state[0]
