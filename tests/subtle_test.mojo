from crypto.subtle import constant_time_compare
from std.testing import TestSuite, assert_false, assert_true


def test_equal_bytes() raises:
    assert_true(constant_time_compare("same".as_bytes(), "same".as_bytes()))


def test_different_bytes() raises:
    assert_false(constant_time_compare("same".as_bytes(), "sand".as_bytes()))


def test_different_lengths() raises:
    assert_false(constant_time_compare("a".as_bytes(), "aa".as_bytes()))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
