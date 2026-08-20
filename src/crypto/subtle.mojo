from std.collections import Span


def constant_time_compare(left: Span[Byte, _], right: Span[Byte, _]) -> Bool:
    if len(left) != len(right):
        return False
    var difference = UInt8(0)
    for i in range(len(left)):
        difference |= left[i] ^ right[i]
    return difference == 0
