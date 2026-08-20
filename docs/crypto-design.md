# Pure Mojo `crypto`パッケージ設計

## 目的

このマイルストーンでは、Pure Mojoの暗号ライブラリに必要なハッシュ、定数時間比較、メッセージ認証、鍵導出を実装する。
Goの`crypto`パッケージ群を構成の参考にするが、公開APIにはMojoの型、所有権、エラー処理を用いる。

ライブラリ本体はMojo標準ライブラリだけに依存する。
FFI、Python、OpenSSL、既存の`hash`パッケージには依存しない。

このマイルストーンは実験的リリースとして扱う。
テストベクトルと独立実装による照合は行うが、外部のセキュリティ監査を受けた実装とは表明しない。

## 長期的な範囲

プロジェクトはGoの`crypto`と`x/crypto`に相当する機能を段階的に追加する。
各段階は独立した仕様と実装計画を持つ。

1. ハッシュ、HMAC、HKDF、PBKDF2、定数時間比較
2. ChaCha20、Poly1305、ChaCha20-Poly1305、XChaCha20-Poly1305
3. AES、AES-CTR、AES-GCM
4. Curve25519、Ed25519
5. Argon2、scrypt、bcrypt
6. SSHなどの暗号プロトコル

この仕様が対象とするのは第1段階だけである。

## パッケージ構成

公開パッケージを次のモジュールに分割する。

```text
crypto
├── md5
├── sha256
├── sha512
├── sha3
├── blake2b
├── blake3
├── subtle
├── hmac
├── hkdf
└── pbkdf2
```

`crypto.md5`は`MD5`を公開する。
`crypto.sha256`は`SHA256`を公開する。
`crypto.sha512`は`SHA384`と`SHA512`を公開する。
`crypto.sha3`は`SHA3_256`を公開する。
`crypto.blake2b`は`BLAKE2b`を公開する。
`crypto.blake3`は`BLAKE3`を公開する。

`BLAKE2b`の`digest_size`は1 byte以上64 byte以下とする。
`BLAKE3`のkeyed modeは32-byte鍵だけを受け入れる。
`BLAKE3`の`digest_xof`と`hexdigest_xof`は0以上の出力長を受け入れる。

これらの実装は既存の`hash-mojo`から移し、`crypto`パッケージの実体とする。
各ハッシュ型はMojo標準の`std.hashlib.Hasher` traitに準拠し続ける。
`crypto.__init__`はサブモジュールの型や関数を一括で再公開しない。

HMAC、HKDF、PBKDF2はSHA-256、SHA-384、SHA-512だけを正式にサポートする。
MD5は既存データとの互換用途に限り、新しいセキュリティ用途には使えないことを文書化する。

## 公開API

### HMAC

`crypto.hmac`は次の具象型を公開する。

```mojo
HMAC_SHA256(key: Span[Byte, _])
HMAC_SHA384(key: Span[Byte, _])
HMAC_SHA512(key: Span[Byte, _])
```

各型は次の操作を持つ。

```mojo
update_bytes(mut self, data: Span[Byte, _])
digest(var self) -> List[UInt8]
hexdigest(var self) -> String
verify(var self, expected: Span[Byte, _]) -> Bool
```

`digest`、`hexdigest`、`verify`はHMACの状態を消費する。
状態の`reset`とコピーは公開しない。

短い入力向けに次のワンショット関数を公開する。

```mojo
hmac_sha256(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]
hmac_sha384(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]
hmac_sha512(key: Span[Byte, _], data: Span[Byte, _]) -> List[UInt8]
```

HMAC型は標準`Hasher` traitに準拠しない。
標準`Hasher`は引数なしの初期化と64-bitの`finish`を要求するため、鍵を必須とし完全長のMACを返すHMACの契約を表現できない。

### HKDF

`crypto.hkdf`は各SHA-2方式に`extract`、`expand`、`derive`を公開する。
SHA-256版のシグネチャを次に示す。
SHA-384版とSHA-512版は名前の接尾辞だけが異なる。

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

初期リリースは要求された長さを一度に返す。
段階的に読み出すreader型は含めない。

### PBKDF2

`crypto.pbkdf2`は各SHA-2方式に`derive`を公開する。
SHA-256版のシグネチャを次に示す。

```mojo
derive_sha256(
    password: Span[Byte, _],
    salt: Span[Byte, _],
    iterations: Int,
    length: Int,
) raises -> List[UInt8]
```

SHA-384版とSHA-512版は名前の接尾辞だけが異なる。

### 定数時間比較

`crypto.subtle`は次の関数を公開する。

```mojo
constant_time_compare(
    left: Span[Byte, _],
    right: Span[Byte, _],
) -> Bool
```

このマイルストーンで使わないselect、copy、整数比較は追加しない。

## データと所有権

公開APIのバイト入力は借用した`Span[Byte, _]`で受け取る。
可変長の生成結果は所有された`List[UInt8]`で返す。

ストリーミングHMACは入力を内部のハッシュ状態へ逐次反映する。
確定処理は内部状態を消費するため、確定後の再利用や暗黙の状態コピーは起こらない。

HMACの初期化は鍵をハッシュのブロック長へ正規化し、inner padとouter padをそれぞれのハッシュ状態へ取り込む。
初期化後の構造体は生の鍵を保持しない。

## 暗号処理

HMACはRFC 2104に従う。
SHA-256のブロック長は64 byte、SHA-384とSHA-512のブロック長は128 byteとする。
ブロック長を超える鍵は同じハッシュで短縮し、短い鍵はゼロで補う。
空の鍵は仕様上の有効な入力として受け入れる。

HKDFはRFC 5869に従う。
空のsaltはダイジェスト長と同じ長さのゼロ列として扱う。
`expand`と`derive`は`255 * digest_length` byteまで出力できる。

PBKDF2-HMACはRFC 8018に従う。
ブロック番号は1から始まる32-bitのbig-endian整数としてHMAC入力へ追加する。
反復回数に恣意的な上限は設けない。

## エラー処理

BLAKE2bは範囲外の`digest_size`を`Error`としてraiseする。
BLAKE3は32 byteではない鍵と負のXOF出力長を`Error`としてraiseする。
XOF出力長0は空のダイジェストまたは空文字列を返す。

HMACの初期化、更新、確定は通常の入力でraiseしない。
MACの長さが異なる比較は`False`を返す。

HKDFは負の出力長と`255 * digest_length` byteを超える出力長を`Error`としてraiseする。
出力長0は空の`List[UInt8]`を返す。

PBKDF2は0以下の反復回数、負の出力長、32-bitのブロック番号で表現できない出力長を`Error`としてraiseする。
出力長0は空の`List[UInt8]`を返す。

独自のエラー型と、同じ失敗に対する複数のフォールバック経路は設けない。

## セキュリティ境界

`constant_time_compare`は長さが同じ場合に全バイトのXOR結果を集約し、バイト値に依存する分岐を行わない。
長さが異なる場合は直ちに`False`を返す。

この性質はソースコード上のbest effortであり、コンパイラとCPUを含む厳密な実行時間を保証しない。
ライブラリは秘密値の確実なゼロ化も保証しない。
現在のMojoでは、最適化後に消去処理が残ることをAPIから保証できないためである。

実装は秘密値の不要なコピーを避ける。
ただし、コピーの回避を秘密値消去の保証として説明しない。

Mojo標準の`std.random`は暗号学的に安全ではないため使用しない。
暗号学的乱数生成はこのマイルストーンの範囲外とする。

## テスト

ハッシュには既存の`hash-mojo`テストを移植する。
対象はMD5、SHA-256、SHA-384、SHA-512、SHA3-256、BLAKE2b、BLAKE3である。

HMACはRFC 4231のSHA-256、SHA-384、SHA-512テストベクトルで検証する。
一つの入力を一度に渡した結果と複数回の`update_bytes`で渡した結果が一致することも検証する。
空入力、ブロック長より長い鍵、MACの一致、不一致、長さ違いを含める。

HKDF-SHA-256はRFC 5869のテストベクトルで検証する。
SHA-384版とSHA-512版はGoの独立実装と事前に照合した固定ベクトルで検証する。
長さ0、最大長、最大長超過も検証する。

PBKDF2-HMAC-SHA-2はRFC 7914のベクトルとGoの独立実装に照合した固定ベクトルで検証する。
反復回数1、複数ブロック出力、長さ0、不正な反復回数を含める。

固定ベクトルはMojoテストへ埋め込む。
テスト実行時にGo、Python、OpenSSLを呼び出さない。

各テストファイルは`std.testing.TestSuite.discover_tests`を使い、`mojo run`で実行する。
precompileした`crypto.mojoc`だけをimportするconsumer testも用意する。

## CIと配布

PixiはMojo 1.0系を管理し、標準ライブラリ以外のライブラリ依存を追加しない。
対象プラットフォームはLinux x86-64とmacOS arm64とする。

CIは次の処理を実行する。

1. Mojoソースとテストのformat確認
2. 全テストの実行
3. `crypto`パッケージのprecompile
4. precompile済みパッケージを使うconsumer test

`conda.recipe`は`crypto`というパッケージ名で`crypto.mojoc`を生成する。
配布先はprefix.devの個人channelを想定する。

READMEは公開API、実行方法、配布方法、実験的リリースであることを説明する。
READMEはMD5の用途制限、一定時間実行、秘密値消去、外部監査の各境界を明記する。

## 対象外

次の項目はこのマイルストーンに含めない。

- SHA-224とSHA-1
- HMAC-SHA3とHMAC-BLAKE
- HKDFのreader API
- 状態のreset、clone、serialize
- 暗号学的乱数生成
- FIPS 140への準拠表明
- SIMDまたはアセンブリによる最適化
- ベンチマーク上の性能目標
- prefix.dev上の既存`hash`パッケージの削除操作

既存`hash`パッケージの削除は、`crypto`パッケージのテスト、precompile、配布確認が完了した後に別作業として行う。
