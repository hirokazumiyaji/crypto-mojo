from std.collections import List, Span

comptime _HEX_DIGITS: StaticString = "0123456789abcdef"


def bytes_to_hex(data: List[UInt8]) -> String:
    var output = String()
    for value in data:
        output += _HEX_DIGITS[byte=Int(value >> 4)]
        output += _HEX_DIGITS[byte=Int(value & 0x0F)]
    return output^


def rotate_left_u32(value: UInt32, shift: Int) -> UInt32:
    return (value << UInt32(shift)) | (value >> UInt32(32 - shift))


def rotate_right_u32(value: UInt32, shift: Int) -> UInt32:
    return (value >> UInt32(shift)) | (value << UInt32(32 - shift))


def rotate_left_u64(value: UInt64, shift: Int) -> UInt64:
    # Guarded because SHA-3 rotates lane 0 by 0, and a 64-bit shift is UB.
    if shift == 0:
        return value
    return (value << UInt64(shift)) | (value >> UInt64(64 - shift))


def rotate_right_u64(value: UInt64, shift: Int) -> UInt64:
    return (value >> UInt64(shift)) | (value << UInt64(64 - shift))


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
    output.append((value & 0xFF).cast[DType.uint8]())
    output.append(((value >> 8) & 0xFF).cast[DType.uint8]())
    output.append(((value >> 16) & 0xFF).cast[DType.uint8]())
    output.append(((value >> 24) & 0xFF).cast[DType.uint8]())


def append_le_u64(mut output: List[UInt8], value: UInt64):
    for i in range(8):
        output.append(((value >> UInt64(i * 8)) & 0xFF).cast[DType.uint8]())


def append_be_u32(mut output: List[UInt8], value: UInt32):
    output.append(((value >> 24) & 0xFF).cast[DType.uint8]())
    output.append(((value >> 16) & 0xFF).cast[DType.uint8]())
    output.append(((value >> 8) & 0xFF).cast[DType.uint8]())
    output.append((value & 0xFF).cast[DType.uint8]())


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
