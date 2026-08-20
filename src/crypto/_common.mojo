from std.collections import List, Span

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
    var output = String(capacity=len(data) * 2)
    for value in data:
        output += _HEX_DIGITS[byte=Int(value >> 4)]
        output += _HEX_DIGITS[byte=Int(value & 0x0F)]
    return output^


def read_le_u32(data: Span[Byte, _], offset: Int) -> UInt32:
    var value = data[offset].cast[DType.uint32]()
    value |= data[offset + 1].cast[DType.uint32]() << UInt32(8)
    value |= data[offset + 2].cast[DType.uint32]() << UInt32(16)
    value |= data[offset + 3].cast[DType.uint32]() << UInt32(24)
    return value


def read_le_u64(data: Span[Byte, _], offset: Int) -> UInt64:
    var value = UInt64(0)
    for i in range(8):
        value |= data[offset + i].cast[DType.uint64]() << UInt64(i * 8)
    return value


def read_be_u32(data: Span[Byte, _], offset: Int) -> UInt32:
    var value = data[offset].cast[DType.uint32]() << UInt32(24)
    value |= data[offset + 1].cast[DType.uint32]() << UInt32(16)
    value |= data[offset + 2].cast[DType.uint32]() << UInt32(8)
    value |= data[offset + 3].cast[DType.uint32]()
    return value


def read_be_u64(data: Span[Byte, _], offset: Int) -> UInt64:
    var value = UInt64(0)
    for i in range(8):
        value |= data[offset + i].cast[DType.uint64]() << UInt64(56 - i * 8)
    return value


def write_le_u64[
    size: Int
](mut buffer: InlineArray[UInt8, size], offset: Int, value: UInt64):
    for i in range(8):
        buffer[offset + i] = ((value >> UInt64(i * 8)) & 0xFF).cast[
            DType.uint8
        ]()


def write_be_u64[
    size: Int
](mut buffer: InlineArray[UInt8, size], offset: Int, value: UInt64):
    for i in range(8):
        buffer[offset + i] = ((value >> UInt64(56 - i * 8)) & 0xFF).cast[
            DType.uint8
        ]()


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
