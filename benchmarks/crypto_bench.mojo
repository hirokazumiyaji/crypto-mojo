# Microbenchmarks for crypto primitives.
# Run with: pixi run bench
# These print throughput only — CI does not gate on the numbers.

from crypto.blake2b import BLAKE2b
from crypto.blake3 import BLAKE3
from crypto.hmac import hmac_sha256
from crypto.hkdf import expand_sha256, extract_sha256, reader_sha256
from crypto.pbkdf2 import derive_sha256 as pbkdf2_sha256
from crypto.rand import fill
from crypto.sha256 import SHA256
from crypto.sha3 import SHA3_256
from crypto.sha512 import SHA512
from std.benchmark import (
    Bench,
    BenchConfig,
    Bencher,
    BenchId,
    BenchMetric,
    ThroughputMeasure,
    keep,
)
from std.collections import List


comptime _SIZE_1K = 1024
comptime _SIZE_64K = 64 * 1024
comptime _PBKDF2_ITERS = 1000


def _filled(length: Int, value: UInt8 = 0xA5) -> List[UInt8]:
    return List[UInt8](length=length, fill=value)


def _bytes_measure(nbytes: Int) -> List[ThroughputMeasure]:
    return [ThroughputMeasure(BenchMetric.bytes, nbytes)]


@always_inline
def _bench_sha256_1k(mut b: Bencher) raises capturing:
    var buf = _filled(_SIZE_1K)

    @always_inline
    def work() raises capturing:
        var hasher = SHA256()
        hasher.update_bytes(buf[:])
        var digest = hasher^.digest()
        keep(digest[0])

    b.iter[work]()
    keep(buf[0])


@always_inline
def _bench_sha256_64k(mut b: Bencher) raises capturing:
    var buf = _filled(_SIZE_64K)

    @always_inline
    def work() raises capturing:
        var hasher = SHA256()
        hasher.update_bytes(buf[:])
        var digest = hasher^.digest()
        keep(digest[0])

    b.iter[work]()
    keep(buf[0])


@always_inline
def _bench_sha512_64k(mut b: Bencher) raises capturing:
    var buf = _filled(_SIZE_64K)

    @always_inline
    def work() raises capturing:
        var hasher = SHA512()
        hasher.update_bytes(buf[:])
        var digest = hasher^.digest()
        keep(digest[0])

    b.iter[work]()
    keep(buf[0])


@always_inline
def _bench_sha3_256_64k(mut b: Bencher) raises capturing:
    var buf = _filled(_SIZE_64K)

    @always_inline
    def work() raises capturing:
        var hasher = SHA3_256()
        hasher.update_bytes(buf[:])
        var digest = hasher^.digest()
        keep(digest[0])

    b.iter[work]()
    keep(buf[0])


@always_inline
def _bench_blake2b_64k(mut b: Bencher) raises capturing:
    var buf = _filled(_SIZE_64K)

    @always_inline
    def work() raises capturing:
        var hasher = BLAKE2b()
        hasher.update_bytes(buf[:])
        var digest = hasher^.digest()
        keep(digest[0])

    b.iter[work]()
    keep(buf[0])


@always_inline
def _bench_blake3_64k(mut b: Bencher) raises capturing:
    var buf = _filled(_SIZE_64K)

    @always_inline
    def work() raises capturing:
        var hasher = BLAKE3()
        hasher.update_bytes(buf[:])
        var digest = hasher^.digest()
        keep(digest[0])

    b.iter[work]()
    keep(buf[0])


@always_inline
def _bench_hmac_sha256_64k(mut b: Bencher) raises capturing:
    var key = _filled(32, 0x0B)
    var msg = _filled(_SIZE_64K)

    @always_inline
    def work() raises capturing:
        var tag = hmac_sha256(key[:], msg[:])
        keep(tag[0])

    b.iter[work]()
    keep(key[0])
    keep(msg[0])


@always_inline
def _bench_hkdf_expand_1k(mut b: Bencher) raises capturing:
    var salt = _filled(16, 0x01)
    var ikm = _filled(32, 0x02)
    var info = _filled(8, 0x03)
    var prk = extract_sha256(salt[:], ikm[:])

    @always_inline
    def work() raises capturing:
        var okm = expand_sha256(prk[:], info[:], 1024)
        keep(okm[0])

    b.iter[work]()
    keep(prk[0])
    keep(info[0])


@always_inline
def _bench_hkdf_reader_1k(mut b: Bencher) raises capturing:
    var salt = _filled(16, 0x01)
    var ikm = _filled(32, 0x02)
    var info = _filled(8, 0x03)
    var prk = extract_sha256(salt[:], ikm[:])

    @always_inline
    def work() raises capturing:
        var reader = reader_sha256(prk[:], info[:])
        var okm = reader.read(1024)
        keep(okm[0])

    b.iter[work]()
    keep(prk[0])
    keep(info[0])


@always_inline
def _bench_pbkdf2_sha256(mut b: Bencher) raises capturing:
    var password = _filled(16, 0x70)
    var salt = _filled(16, 0x73)

    @always_inline
    def work() raises capturing:
        var out = pbkdf2_sha256(password[:], salt[:], _PBKDF2_ITERS, 32)
        keep(out[0])

    b.iter[work]()
    keep(password[0])
    keep(salt[0])


@always_inline
def _bench_rand_1k(mut b: Bencher) raises capturing:
    var buf = List[UInt8](length=_SIZE_1K, fill=0)

    @always_inline
    def work() raises capturing:
        fill(buf[:])
        keep(buf[0])

    b.iter[work]()
    keep(buf[0])


@always_inline
def _bench_rand_64k(mut b: Bencher) raises capturing:
    var buf = List[UInt8](length=_SIZE_64K, fill=0)

    @always_inline
    def work() raises capturing:
        fill(buf[:])
        keep(buf[0])

    b.iter[work]()
    keep(buf[0])


def main() raises:
    var m = Bench(BenchConfig())

    m.bench_function[_bench_sha256_1k](
        BenchId("sha256/1KiB"), _bytes_measure(_SIZE_1K)
    )
    m.bench_function[_bench_sha256_64k](
        BenchId("sha256/64KiB"), _bytes_measure(_SIZE_64K)
    )
    m.bench_function[_bench_sha512_64k](
        BenchId("sha512/64KiB"), _bytes_measure(_SIZE_64K)
    )
    m.bench_function[_bench_sha3_256_64k](
        BenchId("sha3_256/64KiB"), _bytes_measure(_SIZE_64K)
    )
    m.bench_function[_bench_blake2b_64k](
        BenchId("blake2b/64KiB"), _bytes_measure(_SIZE_64K)
    )
    m.bench_function[_bench_blake3_64k](
        BenchId("blake3/64KiB"), _bytes_measure(_SIZE_64K)
    )
    m.bench_function[_bench_hmac_sha256_64k](
        BenchId("hmac_sha256/64KiB"), _bytes_measure(_SIZE_64K)
    )
    m.bench_function[_bench_hkdf_expand_1k](
        BenchId("hkdf_expand_sha256/1KiB"), _bytes_measure(1024)
    )
    m.bench_function[_bench_hkdf_reader_1k](
        BenchId("hkdf_reader_sha256/1KiB"), _bytes_measure(1024)
    )
    m.bench_function[_bench_pbkdf2_sha256](
        BenchId("pbkdf2_sha256/1000iters"),
        [ThroughputMeasure(BenchMetric.elements, 1)],
        fixed_iterations=20,
    )
    m.bench_function[_bench_rand_1k](
        BenchId("rand_fill/1KiB"), _bytes_measure(_SIZE_1K)
    )
    m.bench_function[_bench_rand_64k](
        BenchId("rand_fill/64KiB"), _bytes_measure(_SIZE_64K)
    )

    m.dump_report()
