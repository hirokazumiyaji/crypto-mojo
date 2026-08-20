from std.collections import Span


def constant_time_compare(left: Span[Byte, _], right: Span[Byte, _]) -> Bool:
    if len(left) != len(right):
        return False
    var difference = UInt8(0)
    for i in range(len(left)):
        var left_byte = left[i].cast[DType.uint8]()
        var right_byte = right[i].cast[DType.uint8]()
        difference |= left_byte ^ right_byte
    return difference == 0
