from crypto.rand import bytes, fill
from std.collections import List
from std.testing import TestSuite, assert_equal, assert_raises, assert_true


def test_rand_bytes_zero() raises:
    var empty = bytes(0)
    assert_equal(len(empty), 0)


def test_rand_bytes_length() raises:
    var data = bytes(32)
    assert_equal(len(data), 32)


def test_rand_fill() raises:
    var buf = List[UInt8](length=16, fill=0)
    fill(buf[:])
    var saw_nonzero = False
    for b in buf:
        if b != 0:
            saw_nonzero = True
    assert_true(saw_nonzero)


def test_rand_fill_empty() raises:
    var empty = List[UInt8]()
    fill(empty[:])
    assert_equal(len(empty), 0)


def test_rand_successive_differ() raises:
    var a = bytes(32)
    var b = bytes(32)
    assert_true(a != b)


def test_rand_negative_length() raises:
    with assert_raises():
        _ = bytes(-1)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
