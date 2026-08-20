# crypto-mojo

English | [日本語](README.ja.md)

`crypto-mojo` is a package of cryptographic primitives implemented with only the Mojo standard library, with one exception: `crypto.rand` reads from the OS CSPRNG.

This release is experimental and has not received an external security audit.
Before adopting it for production security use, evaluate the implementation and your operational constraints yourself.

## Public modules

Hash types conform to Mojo's standard `std.hashlib.Hasher` trait.
`digest()` and `hexdigest()` return the full cryptographic digest, while `finish()` returns the 64-bit value required by the standard trait.

```mojo
from crypto.md5 import MD5
from crypto.sha1 import SHA1
from crypto.sha256 import SHA224, SHA256
from crypto.sha512 import SHA384, SHA512
from crypto.sha3 import SHA3_256
from crypto.blake2b import BLAKE2b
from crypto.blake3 import BLAKE3

var sha256 = SHA256()
sha256.update_bytes("abc".as_bytes())
print(sha256^.hexdigest())
```

`BLAKE2b` accepts a `digest_size` from 1 to 64 bytes.
`BLAKE3` provides keyed hashing with a 32-byte key, plus variable-length output of length 0 or greater via `digest_xof()` and `hexdigest_xof()`.

Use MD5 and SHA-1 only to check compatibility with existing data or legacy formats.
Neither is suitable for new designs that need collision resistance, or for signatures, certificates, or password storage.

Every hash type also provides `clone()` and `reset()`.
`clone()` returns an independent copy of the current state; `reset()` returns the instance to its post-construction state (preserving `BLAKE2b`'s `digest_size` and `BLAKE3`'s key, if any). `digest()`, `hexdigest()`, and `finish()` remain consuming, so call `clone()` first if you need both a digest and a continued stream.

HMAC provides streaming types and one-shot functions for SHA-256, SHA-384, SHA-512, SHA3-256, BLAKE2b, and BLAKE3.

```mojo
from crypto.hmac import HMAC_SHA256, hmac_sha256

var key = "secret".as_bytes()
var mac = HMAC_SHA256(key)
mac.update_bytes("message".as_bytes())
var tag = mac^.digest()

var one_shot_tag = hmac_sha256(key, "message".as_bytes())
```

`HMAC_SHA3_256` / `hmac_sha3_256`, `HMAC_BLAKE2b` / `hmac_blake2b`, and `HMAC_BLAKE3` / `hmac_blake3` follow the same shape.
`HMAC_BLAKE2b` fixes the digest size at 64 bytes; `HMAC_BLAKE3` uses BLAKE3's default unkeyed mode with a 32-byte digest, distinct from BLAKE3's own keyed-hash feature.

Every HMAC type also provides `clone()` and `reset()`.
`reset()` restores the keyed inner/outer state captured when the HMAC was constructed, so you can authenticate a new message with the same key without storing or re-deriving the raw key. `digest()`, `hexdigest()`, and `verify()` still consume the value; `reset()` is unavailable afterward.

HKDF and PBKDF2 expose concrete functions for SHA-256, SHA-384, and SHA-512.

```mojo
from crypto.hkdf import derive_sha256 as hkdf_sha256
from crypto.pbkdf2 import derive_sha256 as pbkdf2_sha256

var key_material = hkdf_sha256(
    "input key material".as_bytes(),
    "salt".as_bytes(),
    "context".as_bytes(),
    32,
)
var password_key = pbkdf2_sha256(
    "password".as_bytes(), "salt".as_bytes(), 100_000, 32
)
```

HKDF also exposes an incremental reader for SHA-256, SHA-384, and SHA-512 (`HKDF_SHA256` / `reader_sha256`, and the `384`/`512` equivalents) for callers that need Expand output split across multiple calls instead of one length up front.

```mojo
from crypto.hkdf import extract_sha256, reader_sha256

var prk = extract_sha256("salt".as_bytes(), "input key material".as_bytes())
var reader = reader_sha256(prk[:], "context".as_bytes())
var first_half = reader.read(16)
var second_half = reader.read(16)
```

`read(n)` raises if `n` is negative or if the cumulative bytes read would exceed `255 * digest_size`.
`reset()` rewinds the reader to the start of Expand for the same PRK/info without re-running `extract`.
`clone()` forks an independent copy of the current expansion cursor.

To compare equal-length byte sequences, use `crypto.subtle`.

```mojo
from crypto.subtle import constant_time_compare

var matches = constant_time_compare(
    "expected".as_bytes(), "candidate".as_bytes()
)
```

`constant_time_compare()` aggregates differences across all bytes for equal-length inputs, but it does not guarantee strict timing across the compiler and CPU.
The library also does not guarantee reliable zeroization of secret values.
Current Mojo cannot guarantee from the public API that wipe operations survive optimization.

`crypto.rand` fills byte buffers from the OS CSPRNG (`/dev/urandom`), not Mojo's non-cryptographic `std.random`.

```mojo
from crypto.rand import bytes, fill

var key = bytes(32)

var nonce = List[UInt8](length=12, fill=0)
fill(nonce[:])
```

`bytes(n)` raises if `n` is negative and returns an empty list for `n == 0`.
`fill()` completely fills the given buffer, retrying on short OS reads, and raises only if it cannot read OS entropy at all.

## Local development

Pixi manages Mojo 1.0 and lockfiles for `osx-arm64` and `linux-64`.

```bash
pixi install --locked
pixi run format
pixi run test
pixi run test-consumer
pixi run bench
```

Use tasks such as `pixi run test-sha256` for individual tests.
`test-consumer` precompiles `crypto.mojoc` into `/tmp` and verifies post-distribution imports without adding `src` to the import path.

`pixi run bench` runs microbenchmarks under `benchmarks/` via Mojo's `std.benchmark` and prints throughput (for example GB/s for hashing).
It is a measurement harness only — CI does not enforce performance targets.

To use the precompiled package from an arbitrary local Mojo program:

```bash
mkdir -p /tmp/crypto-mojo/lib/mojo
pixi run mojo precompile src/crypto -o /tmp/crypto-mojo/lib/mojo/crypto.mojoc
pixi run mojo run -I /tmp/crypto-mojo/lib/mojo your_program.mojo
```

## conda package

The recipe installs `crypto.mojoc` into `${PREFIX}/lib/mojo`.

```bash
pixi global install rattler-build
rattler-build build \
  --recipe conda.recipe/recipe.yaml \
  -c conda-forge \
  -c https://conda.modular.com/max
```

The GitHub Actions publish workflow accepts only `v*.*.*` tags and manual runs, and builds packages for Linux x86-64 and macOS arm64.
When publishing from a tag, keep the tag version aligned with `context.version` in the recipe.

Before publishing, set the repository variable `PREFIX_CHANNEL` and the repository secret `PREFIX_API_KEY`.
The workflow does not pass the API key as a command argument and does not print it in logs.
