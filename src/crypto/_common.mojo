from std.bit import byte_swap
from std.collections import List, Span
from std.memory import bitcast, unsafe_memcpy

comptime _HEX_DIGITS: StaticString = "0123456789abcdef"


trait HashFunction(Copyable, Defaultable, Deinitable, Movable):
    """A block-based hash with the streaming interface HMAC needs."""

    comptime block_size: Int
    comptime digest_size: Int

    def update_bytes(mut self, data: Span[Byte, _]):
        ...

    def digest(var self) -> List[UInt8]:
        ...


def bytes_to_hex(data: List[UInt8]) -> String:
    var output = String(capacity_bytes=len(data) * 2)
    for value in data:
        output += _HEX_DIGITS[byte=Int(value >> 4)]
        output += _HEX_DIGITS[byte=Int(value & 0x0F)]
    return output^


@always_inline
def read_le_u32(data: Span[Byte, _], offset: Int) -> UInt32:
    return bitcast[DType.uint32, 1](
        data.unsafe_ptr().unsafe_offset(offset).unsafe_load[width=4]()
    )


@always_inline
def read_le_u64(data: Span[Byte, _], offset: Int) -> UInt64:
    return bitcast[DType.uint64, 1](
        data.unsafe_ptr().unsafe_offset(offset).unsafe_load[width=8]()
    )


@always_inline
def read_be_u32(data: Span[Byte, _], offset: Int) -> UInt32:
    return byte_swap(read_le_u32(data, offset))


@always_inline
def read_be_u64(data: Span[Byte, _], offset: Int) -> UInt64:
    return byte_swap(read_le_u64(data, offset))


@always_inline
def load_le_u32_words[
    count: Int
](data: Span[Byte, _], offset: Int) -> SIMD[DType.uint32, count]:
    return bitcast[DType.uint32, count](
        data.unsafe_ptr().unsafe_offset(offset).unsafe_load[width=count * 4]()
    )


@always_inline
def load_le_u64_words[
    count: Int
](data: Span[Byte, _], offset: Int) -> SIMD[DType.uint64, count]:
    return bitcast[DType.uint64, count](
        data.unsafe_ptr().unsafe_offset(offset).unsafe_load[width=count * 8]()
    )


@always_inline
def copy_to_buffer[
    size: Int
](
    mut buffer: Array[UInt8, size],
    offset: Int,
    data: Span[Byte, _],
    start: Int,
    count: Int,
):
    unsafe_memcpy(
        dest=buffer.unsafe_ptr().unsafe_offset(offset),
        src=data.unsafe_ptr().unsafe_offset(start),
        count=count,
    )


@always_inline
def write_le_u64[
    size: Int
](mut buffer: Array[UInt8, size], offset: Int, value: UInt64):
    buffer.unsafe_ptr().unsafe_offset(offset).unsafe_store(
        bitcast[DType.uint8, 8](SIMD[DType.uint64, 1](value))
    )


@always_inline
def write_be_u64[
    size: Int
](mut buffer: Array[UInt8, size], offset: Int, value: UInt64):
    write_le_u64(buffer, offset, byte_swap(value))


def append_le_u32(mut output: List[UInt8], value: UInt32):
    for i in range(4):
        output.append(((value >> UInt32(i * 8)) & 0xFF).cast[DType.uint8]())


def append_le_u64(mut output: List[UInt8], value: UInt64):
    for i in range(8):
        output.append(((value >> UInt64(i * 8)) & 0xFF).cast[DType.uint8]())


def append_be_u32(mut output: List[UInt8], value: UInt32):
    for i in range(4):
        output.append(
            ((value >> UInt32(24 - i * 8)) & 0xFF).cast[DType.uint8]()
        )


def append_be_u64(mut output: List[UInt8], value: UInt64):
    for i in range(8):
        output.append(
            ((value >> UInt64(56 - i * 8)) & 0xFF).cast[DType.uint8]()
        )


def simd_lanes_le_u64(value: SIMD[_, _]) -> List[UInt8]:
    var bits = value.to_bits()
    var bytes = List[UInt8](capacity=8 * value.length)
    comptime for i in range(value.length):
        append_le_u64(bytes, bits[i].cast[DType.uint64]())
    return bytes^


def simd_lanes_be_u64(value: SIMD[_, _]) -> List[UInt8]:
    var bits = value.to_bits()
    var bytes = List[UInt8](capacity=8 * value.length)
    comptime for i in range(value.length):
        append_be_u64(bytes, bits[i].cast[DType.uint64]())
    return bytes^


def simd_lanes_le_u32(value: SIMD[_, _]) -> List[UInt8]:
    var bits = value.to_bits()
    var bytes = List[UInt8](capacity=4 * value.length)
    comptime for i in range(value.length):
        append_le_u32(bytes, bits[i].cast[DType.uint32]())
    return bytes^
