# crypto-mojo

[English](README.md) | 日本語

`crypto-mojo`は、Mojo標準ライブラリだけで実装した暗号プリミティブのパッケージです。ただし`crypto.rand`だけは例外で、OSのCSPRNGから読み取ります。

このリリースは実験段階であり、外部のセキュリティ監査を受けていません。
本番のセキュリティ用途へ採用する場合は、利用側で実装と運用条件を評価してください。

## 公開モジュール

ハッシュ型はMojo標準の`std.hashlib.Hasher` traitに準拠します。
`digest()`と`hexdigest()`は完全な暗号学的ダイジェストを返し、`finish()`は標準traitが要求する64-bit値を返します。

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

`BLAKE2b`の`digest_size`には1から64までのbyte数を指定できます。
`BLAKE3`は32-byte鍵を受け取るkeyed hashと、`digest_xof()`および`hexdigest_xof()`による0以上の長さの可変長出力を提供します。

MD5とSHA-1は既存データや古い形式との互換性確認に限って使用してください。
いずれも衝突耐性が必要な新しい設計、署名、証明書、パスワード保存には適しません。

すべてのハッシュ型は`clone()`と`reset()`も提供します。
`clone()`は現在の状態を独立に複製したものを返し、`reset()`はインスタンスを構築直後の状態へ戻します(`BLAKE2b`の`digest_size`、`BLAKE3`の鍵があればそれも維持されます)。`digest()`、`hexdigest()`、`finish()`は引き続き値を消費するため、ダイジェストを取得しつつストリームを継続したい場合は先に`clone()`してください。

HMACはSHA-256、SHA-384、SHA-512、SHA3-256、BLAKE2b、BLAKE3のストリーミング型とワンショット関数を提供します。

```mojo
from crypto.hmac import HMAC_SHA256, hmac_sha256

var key = "secret".as_bytes()
var mac = HMAC_SHA256(key)
mac.update_bytes("message".as_bytes())
var tag = mac^.digest()

var one_shot_tag = hmac_sha256(key, "message".as_bytes())
```

`HMAC_SHA3_256`/`hmac_sha3_256`、`HMAC_BLAKE2b`/`hmac_blake2b`、`HMAC_BLAKE3`/`hmac_blake3`も同じ形で利用できます。
`HMAC_BLAKE2b`はダイジェスト長を64 byteに固定し、`HMAC_BLAKE3`はBLAKE3の既定のunkeyedモードを32-byteダイジェストで使います。これはBLAKE3自体のkeyed hash機能とは別物です。

すべてのHMAC型も`clone()`と`reset()`を提供します。
`reset()`はHMAC構築時に取得したinner/outerの状態へ復元するため、生の鍵を保持したり再導出したりせずに同じ鍵で新しいメッセージを認証できます。`digest()`、`hexdigest()`、`verify()`は引き続き値を消費し、消費後は`reset()`を使えません。

HKDFとPBKDF2はSHA-256、SHA-384、SHA-512を選べる具象関数を公開します。

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

HKDFはSHA-256、SHA-384、SHA-512向けに段階的なreader（`HKDF_SHA256`/`reader_sha256`、および`384`/`512`版）も提供します。Expandの出力を一度に指定せず、複数回に分けて読み出したい場合に使います。

```mojo
from crypto.hkdf import extract_sha256, reader_sha256

var prk = extract_sha256("salt".as_bytes(), "input key material".as_bytes())
var reader = reader_sha256(prk[:], "context".as_bytes())
var first_half = reader.read(16)
var second_half = reader.read(16)
```

`read(n)`は`n`が負の場合、または累積で読み出したbyte数が`255 * digest_size`を超える場合に例外を発生させます。
`reset()`は同じPRK/infoに対して`extract`を再実行せずにExpandの先頭へ巻き戻します。
`clone()`は現在の展開カーソルを独立した状態として複製します。

同じ長さのバイト列を比較する場合は`crypto.subtle`を利用できます。

```mojo
from crypto.subtle import constant_time_compare

var matches = constant_time_compare(
    "expected".as_bytes(), "candidate".as_bytes()
)
```

`constant_time_compare()`は同じ長さの入力について全バイトの差を集約しますが、コンパイラとCPUを含む厳密な実行時間を保証しません。
ライブラリは秘密値の確実なゼロ化も保証しません。
現在のMojoでは、最適化後に消去処理が残ることを公開APIから保証できないためです。

`crypto.rand`はOSのCSPRNG(`/dev/urandom`)からバイト列を読み取ります。Mojoの非暗号学的な`std.random`は使いません。

```mojo
from crypto.rand import bytes, fill

var key = bytes(32)

var nonce = List[UInt8](length=12, fill=0)
fill(nonce[:])
```

`bytes(n)`は`n`が負の場合に例外を発生させ、`n == 0`の場合は空のリストを返します。
`fill()`は与えられたバッファをOSからの短い読み取りを再試行しながら完全に埋め、OSエントロピーを全く読み取れない場合のみ例外を発生させます。

## ローカル開発

PixiはMojo 1.1.0と`osx-arm64`および`linux-64`のlockfileを管理します。

```bash
pixi install --locked
pixi run format
pixi run test
pixi run test-consumer
pixi run bench
```

個別のテストには`pixi run test-sha256`のようなタスクを利用できます。
`test-consumer`は`crypto.mojoc`を`/tmp`へprecompileし、`src`をimport pathへ加えずに配布後のimportを検証します。

`pixi run bench`は`benchmarks/`配下のマイクロベンチマークをMojoの`std.benchmark`で実行し、スループット（ハッシュならGB/sなど）を表示します。
計測用のハーネスであり、CIは性能目標の合否を判定しません。

ローカルで任意のMojoプログラムからprecompile済みパッケージを使う場合は、次のように実行します。

```bash
mkdir -p /tmp/crypto-mojo/lib/mojo
pixi run mojo precompile src/crypto -o /tmp/crypto-mojo/lib/mojo/crypto.mojoc
pixi run mojo run -I /tmp/crypto-mojo/lib/mojo your_program.mojo
```

## condaパッケージ

recipeは`crypto.mojoc`を`${PREFIX}/lib/mojo`へインストールします。

```bash
pixi global install rattler-build
rattler-build build \
  --recipe conda.recipe/recipe.yaml \
  -c conda-forge \
  -c https://conda.modular.com/max
```

GitHub Actionsのpublish workflowは`v*.*.*`形式のtagと手動実行だけを受け付け、Linux x86-64とmacOS arm64のpackageを作成します。
tagから公開する場合は、tagのversionとrecipeの`context.version`を一致させます。

公開前にrepository variable `PREFIX_CHANNEL`とrepository secret `PREFIX_API_KEY`を設定してください。
workflowはAPI keyをコマンド引数へ渡さず、ログにも出力しません。
