from std.bit import rotate_bits_right
from std.collections import List, Span
from std.hashlib.hasher import Hasher

from ._common import (
    HashFunction,
    append_le_u32,
    bytes_to_hex,
    read_le_u32,
    read_le_u64,
    simd_lanes_le_u32,
)


comptime _IV = [
    UInt32(0x6A09E667),
    UInt32(0xBB67AE85),
    UInt32(0x3C6EF372),
    UInt32(0xA54FF53A),
    UInt32(0x510E527F),
    UInt32(0x9B05688C),
    UInt32(0x1F83D9AB),
    UInt32(0x5BE0CD19),
]

comptime _MESSAGE_SCHEDULE: List[List[Int]] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
]

comptime _CHUNK_START = UInt32(1)
comptime _CHUNK_END = UInt32(2)
comptime _PARENT = UInt32(4)
comptime _ROOT = UInt32(8)
comptime _KEYED_HASH = UInt32(16)


def _g(
    mut v: InlineArray[UInt32, 16],
    a: Int,
    b: Int,
    c: Int,
    d: Int,
    x: UInt32,
    y: UInt32,
):
    v[a] = v[a] + v[b] + x
    v[d] = rotate_bits_right[16](v[d] ^ v[a])
    v[c] = v[c] + v[d]
    v[b] = rotate_bits_right[12](v[b] ^ v[c])
    v[a] = v[a] + v[b] + y
    v[d] = rotate_bits_right[8](v[d] ^ v[a])
    v[c] = v[c] + v[d]
    v[b] = rotate_bits_right[7](v[b] ^ v[c])


def _compress(
    input_cv: InlineArray[UInt32, 8],
    block_words: InlineArray[UInt32, 16],
    counter: UInt64,
    block_len: UInt32,
    flags: UInt32,
) -> InlineArray[UInt32, 16]:
    var v = InlineArray[UInt32, 16](uninitialized=True)
    comptime for i in range(8):
        v[i] = input_cv[i]
        v[i + 8] = materialize[_IV[i]]()
    v[12] = (counter & UInt64(0xFFFFFFFF)).cast[DType.uint32]()
    v[13] = (counter >> UInt64(32)).cast[DType.uint32]()
    v[14] = block_len
    v[15] = flags

    comptime for round in range(7):
        comptime s = _MESSAGE_SCHEDULE[round]
        _g(
            v,
            0,
            4,
            8,
            12,
            block_words[materialize[s[0]]()],
            block_words[materialize[s[1]]()],
        )
        _g(
            v,
            1,
            5,
            9,
            13,
            block_words[materialize[s[2]]()],
            block_words[materialize[s[3]]()],
        )
        _g(
            v,
            2,
            6,
            10,
            14,
            block_words[materialize[s[4]]()],
            block_words[materialize[s[5]]()],
        )
        _g(
            v,
            3,
            7,
            11,
            15,
            block_words[materialize[s[6]]()],
            block_words[materialize[s[7]]()],
        )
        _g(
            v,
            0,
            5,
            10,
            15,
            block_words[materialize[s[8]]()],
            block_words[materialize[s[9]]()],
        )
        _g(
            v,
            1,
            6,
            11,
            12,
            block_words[materialize[s[10]]()],
            block_words[materialize[s[11]]()],
        )
        _g(
            v,
            2,
            7,
            8,
            13,
            block_words[materialize[s[12]]()],
            block_words[materialize[s[13]]()],
        )
        _g(
            v,
            3,
            4,
            9,
            14,
            block_words[materialize[s[14]]()],
            block_words[materialize[s[15]]()],
        )

    var output = InlineArray[UInt32, 16](uninitialized=True)
    for i in range(8):
        output[i] = v[i] ^ v[i + 8]
        output[i + 8] = v[i + 8] ^ input_cv[i]
    return output^


def _bytes_to_words(data: Span[Byte, _]) -> InlineArray[UInt32, 16]:
    var words = InlineArray[UInt32, 16](fill=0)
    var full_words = len(data) // 4
    for i in range(full_words):
        words[i] = read_le_u32(data, i * 4)
    for i in range(full_words * 4, len(data)):
        words[full_words] |= data[i].cast[DType.uint32]() << UInt32(i % 4 * 8)
    return words^


struct _BLAKE3Output:
    var _input_cv: InlineArray[UInt32, 8]
    var _block_words: InlineArray[UInt32, 16]
    var _counter: UInt64
    var _block_len: UInt32
    var _flags: UInt32

    def __init__(
        out self,
        input_cv: InlineArray[UInt32, 8],
        block_words: InlineArray[UInt32, 16],
        counter: UInt64,
        block_len: UInt32,
        flags: UInt32,
    ):
        self._input_cv = input_cv.copy()
        self._block_words = block_words.copy()
        self._counter = counter
        self._block_len = block_len
        self._flags = flags

    def chaining_value(self) -> InlineArray[UInt32, 8]:
        var words = _compress(
            self._input_cv,
            self._block_words,
            self._counter,
            self._block_len,
            self._flags,
        )
        var cv = InlineArray[UInt32, 8](uninitialized=True)
        for i in range(8):
            cv[i] = words[i]
        return cv^

    def root_bytes(self, output_block_counter: UInt64) -> List[UInt8]:
        var words = _compress(
            self._input_cv,
            self._block_words,
            output_block_counter,
            self._block_len,
            self._flags | _ROOT,
        )
        var output = List[UInt8](capacity=64)
        for i in range(16):
            append_le_u32(output, words[i])
        return output^


struct _BLAKE3ChunkState(Copyable, Movable):
    var _cv: InlineArray[UInt32, 8]
    var _chunk_counter: UInt64
    var _block: InlineArray[UInt8, 64]
    var _block_len: Int
    var _blocks_compressed: Int
    var _flags: UInt32

    def __init__(
        out self,
        key_words: InlineArray[UInt32, 8],
        chunk_counter: UInt64,
        flags: UInt32,
    ):
        self._cv = key_words.copy()
        self._chunk_counter = chunk_counter
        self._block = InlineArray[UInt8, 64](fill=0)
        self._block_len = 0
        self._blocks_compressed = 0
        self._flags = flags

    def is_full(self) -> Bool:
        return self._blocks_compressed == 15 and self._block_len == 64

    def _compress_block(mut self):
        var block_span = Span(self._block)
        var words = _bytes_to_words(block_span)
        var flags = self._flags
        if self._blocks_compressed == 0:
            flags |= _CHUNK_START
        var output = _compress(
            self._cv,
            words,
            self._chunk_counter,
            UInt32(64),
            flags,
        )
        for i in range(8):
            self._cv[i] = output[i]
        self._blocks_compressed += 1
        self._block_len = 0

    def update(mut self, data: Span[Byte, _]) -> Int:
        var offset = 0
        while offset < len(data):
            if self.is_full():
                break
            if self._block_len == 64:
                self._compress_block()
            var available = min(64 - self._block_len, len(data) - offset)
            for i in range(available):
                self._block[self._block_len + i] = data[offset + i]
            self._block_len += available
            offset += available
        return offset

    def output(self) -> _BLAKE3Output:
        # Only _block_len bytes are valid; the tail may hold stale data.
        var words = _bytes_to_words(Span(self._block)[: self._block_len])
        var flags = self._flags | _CHUNK_END
        if self._blocks_compressed == 0:
            flags |= _CHUNK_START
        return _BLAKE3Output(
            self._cv,
            words,
            self._chunk_counter,
            UInt32(self._block_len),
            flags,
        )


def _initial_key_words() -> InlineArray[UInt32, 8]:
    var words = InlineArray[UInt32, 8](uninitialized=True)
    comptime for i in range(8):
        words[i] = materialize[_IV[i]]()
    return words^


def _key_words(key: Span[Byte, _]) -> InlineArray[UInt32, 8]:
    var words = InlineArray[UInt32, 8](uninitialized=True)
    for i in range(8):
        words[i] = read_le_u32(key, i * 4)
    return words^


struct _BLAKE3Core(Copyable, Movable):
    # One chaining value per tree level; 54 levels cover the 2^64-byte
    # (2^54-chunk) input limit.
    var _key_words: InlineArray[UInt32, 8]
    var _chunk: _BLAKE3ChunkState
    var _stack: InlineArray[InlineArray[UInt32, 8], 54]
    var _stack_len: Int
    var _flags: UInt32

    def __init__(
        out self,
        key_words: InlineArray[UInt32, 8],
        flags: UInt32,
    ):
        self._key_words = key_words.copy()
        self._chunk = _BLAKE3ChunkState(key_words, 0, flags)
        self._stack = InlineArray[InlineArray[UInt32, 8], 54](
            fill=InlineArray[UInt32, 8](fill=0)
        )
        self._stack_len = 0
        self._flags = flags

    def _parent_output(
        self,
        left: InlineArray[UInt32, 8],
        right: InlineArray[UInt32, 8],
    ) -> _BLAKE3Output:
        var block_words = InlineArray[UInt32, 16](uninitialized=True)
        for i in range(8):
            block_words[i] = left[i]
            block_words[i + 8] = right[i]
        return _BLAKE3Output(
            self._key_words,
            block_words,
            0,
            UInt32(64),
            self._flags | _PARENT,
        )

    def _push_chunk_cv(
        mut self,
        cv: InlineArray[UInt32, 8],
        chunk_counter: UInt64,
    ):
        var total_chunks = chunk_counter + 1
        var current = cv.copy()
        while (total_chunks & UInt64(1)) == 0:
            self._stack_len -= 1
            var parent = self._parent_output(
                self._stack[self._stack_len], current
            )
            current = parent.chaining_value()
            total_chunks >>= UInt64(1)
        self._stack[self._stack_len] = current^
        self._stack_len += 1

    def _finish_chunk(mut self):
        var output = self._chunk.output()
        var cv = output.chaining_value()
        self._push_chunk_cv(cv, self._chunk._chunk_counter)
        self._chunk = _BLAKE3ChunkState(
            self._key_words,
            self._chunk._chunk_counter + 1,
            self._flags,
        )

    def update_bytes(mut self, data: Span[Byte, _]):
        var offset = 0
        while offset < len(data):
            if self._chunk.is_full():
                self._finish_chunk()
            offset += self._chunk.update(data[offset:])

    def _root_output(mut self) -> _BLAKE3Output:
        var output = self._chunk.output()
        var current = output.chaining_value()
        while self._stack_len > 0:
            self._stack_len -= 1
            output = self._parent_output(self._stack[self._stack_len], current)
            current = output.chaining_value()
        return output^

    def digest_xof(mut self, length: Int) -> List[UInt8]:
        var output_node = self._root_output()
        var output = List[UInt8](capacity=length)
        var output_counter = UInt64(0)
        while len(output) < length:
            var block = output_node.root_bytes(output_counter)
            var remaining = length - len(output)
            var available = min(64, remaining)
            for i in range(available):
                output.append(block[i])
            output_counter += 1
        return output^

    def hexdigest_xof(mut self, length: Int) -> String:
        return bytes_to_hex(self.digest_xof(length))

    def digest(mut self) -> List[UInt8]:
        return self.digest_xof(32)

    def hexdigest(mut self) -> String:
        return self.hexdigest_xof(32)

    def finish(mut self) -> UInt64:
        var bytes = self.digest_xof(8)
        return read_le_u64(bytes[:], 0)

    def _update_with_simd(mut self, value: SIMD[_, _]):
        var bytes = simd_lanes_le_u32(value)
        self.update_bytes(bytes[:])


struct BLAKE3(Copyable, Defaultable, HashFunction, Hasher, Movable):
    comptime block_size = 64
    comptime digest_size = 32

    var _core: _BLAKE3Core

    def __init__(out self):
        self._core = _BLAKE3Core(_initial_key_words(), 0)

    def __init__(out self, key: Span[Byte, _]) raises:
        if len(key) != 32:
            raise Error("BLAKE3 key must be exactly 32 bytes")
        self._core = _BLAKE3Core(_key_words(key), _KEYED_HASH)

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
        var key_words = self._core._key_words.copy()
        var flags = self._core._flags
        self._core = _BLAKE3Core(key_words, flags)

    def digest(var self) -> List[UInt8]:
        return self._core.digest()

    def hexdigest(var self) -> String:
        return self._core.hexdigest()

    def digest_xof(var self, length: Int) raises -> List[UInt8]:
        if length < 0:
            raise Error("BLAKE3 XOF length must not be negative")
        return self._core.digest_xof(length)

    def hexdigest_xof(var self, length: Int) raises -> String:
        if length < 0:
            raise Error("BLAKE3 XOF length must not be negative")
        return self._core.hexdigest_xof(length)

    def finish(var self) -> UInt64:
        return self._core.finish()
