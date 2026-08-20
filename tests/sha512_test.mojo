from crypto.sha512 import SHA384, SHA512
from std.collections import List
from std.testing import TestSuite, assert_equal


def test_sha512_empty() raises:
    var hasher = SHA512()
    assert_equal(
        hasher^.hexdigest(),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    )


def test_sha384_empty() raises:
    var hasher = SHA384()
    assert_equal(
        hasher^.hexdigest(),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    )


def test_sha512_known_answers() raises:
    var hasher = SHA512()
    hasher.update_bytes("abc".as_bytes())
    assert_equal(
        hasher^.hexdigest(),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    )


def test_sha384_known_answers() raises:
    var hasher = SHA384()
    hasher.update_bytes("abc".as_bytes())
    assert_equal(
        hasher^.hexdigest(),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    )


def test_sha512_streaming_updates() raises:
    var input = "1234567890" * 8
    var bytes = input.as_bytes()
    var hasher = SHA512()
    var start = 0
    var width = 1
    while start < len(bytes):
        var end = min(start + width, len(bytes))
        hasher.update_bytes(bytes[start:end])
        start = end
        width = (width % 17) + 1
    assert_equal(
        hasher^.hexdigest(),
        "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843",
    )


def test_sha384_streaming_updates() raises:
    var input = "1234567890" * 8
    var bytes = input.as_bytes()
    var hasher = SHA384()
    var start = 0
    var width = 1
    while start < len(bytes):
        var end = min(start + width, len(bytes))
        hasher.update_bytes(bytes[start:end])
        start = end
        width = (width % 17) + 1
    assert_equal(
        hasher^.hexdigest(),
        "b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026",
    )


def test_sha512_binary_input() raises:
    var input = List[UInt8]()
    input.append(0x00)
    input.append(0x01)
    input.append(0x02)
    input.append(0x7F)
    input.append(0x80)
    input.append(0xFE)
    input.append(0xFF)
    var hasher = SHA512()
    hasher.update_bytes(input[:])
    assert_equal(
        hasher^.hexdigest(),
        "48de047982747abfd050fde4218cdbd9227e06a53c5f999c65dce9ffcd28c7a6b00fbf181ace8b00b3af5042095cffec30d63c3906728dd714defd6f31f53209",
    )


def test_sha384_binary_input() raises:
    var input = List[UInt8]()
    input.append(0x00)
    input.append(0x01)
    input.append(0x02)
    input.append(0x7F)
    input.append(0x80)
    input.append(0xFE)
    input.append(0xFF)
    var hasher = SHA384()
    hasher.update_bytes(input[:])
    assert_equal(
        hasher^.hexdigest(),
        "8a50545d5deed1b56516abcd8bcd3f645b675e502c8a1704e9863f8856117fb3fa98f85a40957730fa16525ccebc10ae",
    )


def test_sha512_padding_boundaries() raises:
    var lengths = [111, 112, 113, 127, 128, 129]
    var expected = [
        "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2",
        "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca",
        "55ddd8ac210a6e18ba1ee055af84c966e0dbff091c43580ae1be703bdb85da31acf6948cf5bd90c55a20e5450f22fb89bd8d0085e39f85a86cc46abbca75e24d",
        "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502",
        "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321",
        "4f681e0bd53cda4b5a2041cc8a06f2eabde44fb16c951fbd5b87702f07aeab611565b19c47fde30587177ebb852e3971bbd8d3fd30da18d71037dfbd98420429",
    ]
    for i in range(len(lengths)):
        var input = _repeated_a(lengths[i])
        var hasher = SHA512()
        if i % 2 == 0:
            hasher.update_bytes(input[:])
        else:
            var split = lengths[i] // 2
            hasher.update_bytes(input[:split])
            hasher.update_bytes(input[split:])
        assert_equal(hasher^.hexdigest(), expected[i])


def test_sha384_padding_boundaries() raises:
    var lengths = [111, 112, 113, 127, 128, 129]
    var expected = [
        "3c37955051cb5c3026f94d551d5b5e2ac38d572ae4e07172085fed81f8466b8f90dc23a8ffcdea0b8d8e58e8fdacc80a",
        "187d4e07cb306103c69967bf544d0dfbe9042577599c73c330abc0cb64c61236d5ed565ee19119d8c31779a38f791fcd",
        "1d6bed01626682961b50da078a6b1da707c1da0c8a0a3226f159235bd45ed724a0622fa6f39fd70007a6c72a5cda43ae",
        "9bd06b1763c2cf7aef40e795dc65bc96d59c41b537f3ad72ebdefd485476b5717c1aeb37c327fe9c1831b12b9efd08ae",
        "edb12730a366098b3b2beac75a3bef1b0969b15c48e2163c23d96994f8d1bef760c7e27f3c464d3829f56c0d53808b0b",
        "39b6f5a7b0e781dbc419f72e49b30eaac10f2c98c4403bc610da31067fd1b48f324138c8615d2b496d08d73d5e865326",
    ]
    for i in range(len(lengths)):
        var input = _repeated_a(lengths[i])
        var hasher = SHA384()
        if i % 2 == 0:
            hasher.update_bytes(input[:])
        else:
            var split = lengths[i] // 2
            hasher.update_bytes(input[:split])
            hasher.update_bytes(input[split:])
        assert_equal(hasher^.hexdigest(), expected[i])


def test_sha512_digest_length() raises:
    var digest = SHA512().digest()
    assert_equal(len(digest), 64)


def test_sha384_digest_length() raises:
    var digest = SHA384().digest()
    assert_equal(len(digest), 48)


def test_sha512_finish() raises:
    var empty = SHA512()
    assert_equal(empty^.finish(), 14953042807679334589)
    var short = SHA512()
    short.update_bytes("abc".as_bytes())
    assert_equal(short^.finish(), 15974045371385084602)


def test_sha384_finish() raises:
    var empty = SHA384()
    assert_equal(empty^.finish(), 4084871133771109944)
    var short = SHA384()
    short.update_bytes("abc".as_bytes())
    assert_equal(short^.finish(), 14627820504311094923)


def _repeated_a(length: Int) -> List[UInt8]:
    var input = List[UInt8](capacity=length)
    for _ in range(length):
        input.append(0x61)
    return input^


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
