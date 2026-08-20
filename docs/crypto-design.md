# Pure Mojo `crypto` package design

English | [日本語](crypto-design.ja.md)

## Goals

This milestone implements the hashing, constant-time comparison, message authentication, and key derivation needed for a Pure Mojo cryptography library.
Go's `crypto` packages inform the structure, but the public API uses Mojo types, ownership, and error handling.

Cryptographic primitives use only the Mojo standard library.
`crypto.rand` is the one exception: it may call the OS CSPRNG.
The library does not depend on FFI, Python, OpenSSL, or the existing `hash` package.

Treat this milestone as an experimental release.
We verify against test vectors and independent implementations, but we do not claim an externally audited implementation.

## Long-term scope

The project will add functionality comparable to Go's `crypto` and `x/crypto` in stages.
Each stage has its own specification and implementation plan.

1. Hashing, HMAC, HKDF, PBKDF2, constant-time comparison
2. ChaCha20, Poly1305, ChaCha20-Poly1305, XChaCha20-Poly1305
3. AES, AES-CTR, AES-GCM
4. Curve25519, Ed25519
5. Argon2, scrypt, bcrypt
6. Cryptographic protocols such as SSH

This specification covers only stage 1.

## Package layout

Split the public package into these modules:

```text
crypto
├── md5
├── sha1
├── sha256
├── sha512
├── sha3
├── blake2b
├── blake3
├── subtle
├── hmac
├── hkdf
├── pbkdf2
└── rand
```

`crypto.md5` exports `MD5`.
`crypto.sha1` exports `SHA1`.
`crypto.sha256` exports `SHA224` and `SHA256`.
`crypto.sha512` exports `SHA384` and `SHA512`.
`crypto.sha3` exports `SHA3_256`.
`crypto.blake2b` exports `BLAKE2b`.
`crypto.blake3` exports `BLAKE3`.

`BLAKE2b` `digest_size` is from 1 byte through 64 bytes inclusive.
`BLAKE3` keyed mode accepts only a 32-byte key.
`BLAKE3` `digest_xof` and `hexdigest_xof` accept an output length of 0 or greater.

Move these implementations from the existing `hash-mojo` project and make them the body of the `crypto` package.
Each hash type continues to conform to Mojo's standard `std.hashlib.Hasher` trait.
`crypto.__init__` does not re-export submodule types or functions in bulk.

Every public hash type also provides `clone(self) -> Self` and `reset(mut self)`.
`clone` returns an independent copy of the current intermediate state.
`reset` restores the instance to its post-`__init__` state for that value: an unkeyed hash returns to its empty state, `BLAKE2b` keeps its configured `digest_size`, and keyed `BLAKE3` keeps its key (re-derived from the key words already held internally, so callers do not re-supply the key). `digest`, `hexdigest`, and `finish` remain consuming; `reset` is not available after consumption.

HMAC officially supports SHA-256, SHA-384, SHA-512, SHA3-256, BLAKE2b, and BLAKE3, in addition to the generic `HMAC[H: HashFunction]`.
HKDF and PBKDF2 officially support only SHA-256, SHA-384, and SHA-512.
Document that MD5 and SHA-1 are for compatibility with existing data only and must not be used for new security purposes.

## Public API

### HMAC

`crypto.hmac` exports these concrete types, built from the generic `HMAC[H: HashFunction]`:

```mojo
HMAC_SHA256(key: Span[Byte, _])
HMAC_SHA384(key: Span[Byte, _])
HMAC_SHA512(key: Span[Byte, _])
HMAC_SHA3_256(key: Span[Byte, _])
HMAC_BLAKE2b(key: Span[Byte, _])
HMAC_BLAKE3(key: Span[Byte, _])
```

`SHA3_256`, `BLAKE2b`, and `BLAKE3` conform to `crypto._common.HashFunction` with fixed `block_size` / `digest_size` so `HMAC[H]` type-checks over them: `SHA3_256` is 136/32, `BLAKE2b` is 128/64 (its `Defaultable` construction fixes the output at 64 bytes; the separate `BLAKE2b(digest_size=…)` constructor for variable output remains outside the HMAC path), and `BLAKE3` is 64/32 (its unkeyed default constructor; BLAKE3's keyed-hash mode stays a separate feature, not merged into HMAC).

Each type provides these operations:

```mojo
update_bytes(mut self, data: Span[Byte, _])
digest(var self) -> List[UInt8]
hexdigest(var self) -> String
verify(var self, expected: Span[Byte, _]) -> Bool
clone(self) -> Self
reset(mut self)
```

`digest`, `hexdigest`, and `verify` consume the HMAC state.
`clone` returns an independent copy of the current streaming state.
`reset` restores the keyed inner/outer hash state captured at the end of `__init__`, so a caller can start a new message with the same key without storing or re-deriving the raw key. `reset` is not available after `digest` / `hexdigest` / `verify` have consumed the value.

For short inputs, export these one-shot functions:

```mojo
hmac_sha256(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]
hmac_sha384(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]
hmac_sha512(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]
hmac_sha3_256(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]
hmac_blake2b(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]
hmac_blake3(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]
```

HMAC types do not conform to the standard `Hasher` trait.
The standard `Hasher` requires argument-free initialization and a 64-bit `finish`, so it cannot express HMAC's contract of a required key and a full-length MAC.

### HKDF

`crypto.hkdf` exports `extract`, `expand`, and `derive` for each SHA-2 variant.
The SHA-256 signatures are shown below.
The SHA-384 and SHA-512 variants differ only in the name suffix.

```mojo
extract_sha256(
    salt: Span[Byte, _],
    input_key_material: Span[Byte, _],
) -> List[UInt8]

expand_sha256(
    pseudorandom_key: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]

derive_sha256(
    input_key_material: Span[Byte, _],
    salt: Span[Byte, _],
    info: Span[Byte, _],
    length: Int,
) raises -> List[UInt8]
```

The initial release returns the requested length in one shot.

`crypto.hkdf` also exports an incremental reader for each SHA-2 variant, built from a PRK and info without re-running `extract`.

```mojo
struct HKDF_SHA256:
    def __init__(out self, prk: Span[Byte, _], info: Span[Byte, _])
    def read(mut self, length: Int) raises -> List[UInt8]
    def clone(self) -> Self
    def reset(mut self)

reader_sha256(prk: Span[Byte, _], info: Span[Byte, _]) -> HKDF_SHA256
```

`read(n)` returns the next `n` bytes of Expand output; internal block generation matches the one-shot `expand` function exactly (previous block || info || counter). It raises for negative `n` or when cumulative bytes read would exceed `255 * digest_size`. `reset` rewinds the expansion cursor to the start for the same PRK/info. `clone` forks an independent copy of the cursor. SHA-384 and SHA-512 readers (`HKDF_SHA384` / `reader_sha384`, `HKDF_SHA512` / `reader_sha512`) follow the same shape.

### PBKDF2

`crypto.pbkdf2` exports `derive` for each SHA-2 variant.
The SHA-256 signature is shown below.

```mojo
derive_sha256(
    password: Span[Byte, _],
    salt: Span[Byte, _],
    iterations: Int,
    length: Int,
) raises -> List[UInt8]
```

The SHA-384 and SHA-512 variants differ only in the name suffix.

### Constant-time comparison

`crypto.subtle` exports:

```mojo
constant_time_compare(
    left: Span[Byte, _],
    right: Span[Byte, _],
) -> Bool
```

Do not add select, copy, or integer comparison helpers unused in this milestone.

### Random numbers

`crypto.rand` exports:

```mojo
fill(dest: Span[mut=True, Byte, _]) raises
bytes(length: Int) raises -> List[UInt8]
```

`fill` completely fills `dest` by reading `/dev/urandom`, retrying on short reads; it raises only on a hard failure to read OS entropy. `bytes(n)` returns `n` random bytes; `n < 0` raises, and `n == 0` returns an empty list. `crypto.rand` does not publish a Go-style global `Reader` trait object, and it does not implement a userspace DRBG.

## Data and ownership

Public API byte inputs are borrowed `Span[Byte, _]`.
Variable-length outputs are owned `List[UInt8]`.

Streaming HMAC folds input into internal hash state incrementally.
Finalization consumes that state, so reuse or implicit state copies after finalization do not occur.

HMAC initialization normalizes the key to the hash block size and absorbs the inner and outer pads into separate hash states.
After initialization, the struct does not retain the raw key.

## Cryptographic processing

HMAC follows RFC 2104.
SHA-256 uses a 64-byte block size; SHA-384 and SHA-512 use a 128-byte block size.
Keys longer than the block size are shortened with the same hash; shorter keys are zero-padded.
Empty keys are accepted as valid inputs per the specification.

HKDF follows RFC 5869.
An empty salt is treated as a zero string of digest length.
`expand` and `derive` may produce up to `255 * digest_length` bytes.

PBKDF2-HMAC follows RFC 8018.
Block numbers are appended to the HMAC input as 32-bit big-endian integers starting at 1.
Do not impose an arbitrary iteration-count ceiling.

## Error handling

BLAKE2b raises `Error` for out-of-range `digest_size`.
BLAKE3 raises `Error` for keys that are not 32 bytes and for negative XOF output lengths.
An XOF output length of 0 returns an empty digest or empty string.

HMAC initialization, update, and finalization do not raise for ordinary inputs.
MAC comparisons with mismatched lengths return `False`.

HKDF raises `Error` for negative output lengths and for lengths greater than `255 * digest_length` bytes.
An output length of 0 returns an empty `List[UInt8]`.

PBKDF2 raises `Error` for non-positive iteration counts, negative output lengths, and output lengths that cannot be expressed with 32-bit block numbers.
An output length of 0 returns an empty `List[UInt8]`.

Do not introduce custom error types or multiple fallback paths for the same failure.

## Security boundaries

`constant_time_compare` aggregates XOR differences across all bytes when lengths match and does not branch on byte values.
When lengths differ, it returns `False` immediately.

This property is best-effort at the source level and does not guarantee strict timing across the compiler and CPU.
The library also does not guarantee reliable zeroization of secret values.
Current Mojo cannot guarantee from the API that wipe operations survive optimization.

Implementations avoid unnecessary copies of secret values.
Do not describe copy avoidance as a guarantee of secret zeroization.

Do not use Mojo's standard `std.random`; it is not cryptographically secure.
`crypto.rand` reads directly from the OS CSPRNG (`/dev/urandom` on Linux and macOS) instead.

## Testing

Port the existing `hash-mojo` tests for hashing.
Cover MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, BLAKE2b, and BLAKE3.
Verify SHA-1 and SHA-224 against well-known fixed vectors, including empty input, short ASCII input, and multi-`update_bytes` versus one-shot input.

Verify HMAC against RFC 4231 test vectors for SHA-256, SHA-384, and SHA-512.
Also verify that passing one input at once matches results from multiple `update_bytes` calls.
Include empty inputs, keys longer than the block size, matching MACs, mismatched MACs, and length mismatches.

Verify HMAC-SHA3-256 against published test vectors.
Verify HMAC-BLAKE2b and HMAC-BLAKE3 against fixed vectors embedded after offline cross-check against an independent implementation.
Also verify that streaming `update_bytes` calls match the one-shot functions.

Verify HKDF-SHA-256 against RFC 5869 test vectors.
Verify SHA-384 and SHA-512 with fixed vectors previously checked against an independent Go implementation.
Also cover length 0, maximum length, and over-maximum length.

Verify that the HKDF reader's `read` matches `expand` for an equal total length, that sequential reads across block boundaries concatenate to the same bytes as a single `expand` call, that `clone` diverges independently from the original reader, that `reset` replays the same bytes as the original run, and that reading past the maximum length raises.

For each public hash type and HMAC alias, verify that `update` → `clone` → further diverging updates produce different digests, and that `update` → `reset` → re-feeding the same input matches a freshly constructed hasher or HMAC. For HMAC specifically, verify that `reset` preserves keying (a reset-then-fed MAC matches the one-shot function for the same key and message) without needing to re-supply the key.

Verify PBKDF2-HMAC-SHA-2 against RFC 7914 vectors and fixed vectors checked against an independent Go implementation.
Include one iteration, multi-block output, length 0, and invalid iteration counts.

Verify `crypto.rand` with empty `fill` / `bytes(0)`, that requested lengths are honored, that successive outputs differ with high probability, and that a negative length raises. There are no fixed keystream vectors, since OS entropy is non-deterministic.

Embed fixed vectors in the Mojo tests.
Do not call Go, Python, or OpenSSL at test time.

Each test file uses `std.testing.TestSuite.discover_tests` and runs with `mojo run`.
Also provide a consumer test that imports only the precompiled `crypto.mojoc`.

## CI and distribution

Pixi manages Mojo 1.0 and adds no library dependencies beyond the standard library.
Target platforms are Linux x86-64 and macOS arm64.

CI runs:

1. Format checks for Mojo sources and tests
2. The full test suite
3. Precompilation of the `crypto` package
4. A consumer test against the precompiled package

`conda.recipe` produces `crypto.mojoc` under the package name `crypto`.
Distribution is intended for a personal prefix.dev channel.

The README documents the public API, how to run and distribute the package, and that the release is experimental.
It also states the boundaries for MD5 use, constant-time execution, secret zeroization, and external audit status.

## Out of scope

This milestone does not include:

- Serialize/deserialize of hash, HMAC, or HKDF reader state
- FIPS 140 compliance claims
- SIMD or assembly optimization
- Benchmark performance targets (a local `pixi run bench` harness exists for measurement only; CI does not enforce numbers)
- Deleting the existing `hash` package on prefix.dev

Deleting the existing `hash` package is a separate task after `crypto` package tests, precompilation, and distribution checks are complete.
