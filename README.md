# service-account

複数のサービスのログインをまとめる認証サービス。

- ログイン画面とアカウント設定画面を、このサービスのドメイン（例: `auth.example.com`）1 か所に置く。パスワードマネージャの保存先もパスキーの RP ID もこのドメインになり、ドメインの違うサービス同士で共有できる
- ログイン: パスワード / パスキー（WebAuthn）
- アカウント操作: パスワードの変更・追加・削除、パスキーの登録・一覧・削除
- ログイン状態（セッション）は持たない。各サービスはログイントークン（短命な JWT）を検証して、自分のセッションを作る
- ユーザー登録: サーバー上の CLI からだけ行う
- 保存先: SQLite
- 配布: GraalVM の native image を distroless に載せた Docker イメージ

1 つのプロセスで 2 つのサーバーを立ち上げる。

| ID | ポート | 相手 | 内容 |
| --- | --- | --- | --- |
| 1 | HTTP（既定 8080） | ブラウザ・アプリ | ログイン画面、アカウント設定画面、REST、`assetlinks.json` |
| 2 | gRPC（既定 50051） | 各サービスのバックエンド | 認可コードの交換、ログイントークンの検証、JWKS |

## Web のログイン

OAuth 2.0 の認可コードフロー（PKCE は S256 だけ）。

1. 各サービスがブラウザを `https://auth.example.com/authorize` へ送る。パラメーターは `response_type=code`・`client_id`・`redirect_uri`・`state`・`code_challenge`・`code_challenge_method=S256`
2. ログイン画面でパスワードかパスキーでログインすると、`redirect_uri?code=...&state=...` に戻る
3. バックエンドが gRPC の `ExchangeAuthorizationCode` でコードをログイントークンに交換する。結果にユーザー ID とユーザー名も入る
4. バックエンドが自分のセッションを作る

`redirect_uri` は設定ファイルに登録したものと完全一致で比べる。

## アプリのログイン

アプリは HTTP の REST を直接呼ぶ。

1. `POST /api/login/password`（または `/api/login/passkey`）に `clientId` を付けて送ると、`loginToken` と `accountToken` が返る
2. `loginToken` を自分のバックエンドに渡す。バックエンドは gRPC の `VerifyLoginToken` か、`GetJwks` の公開鍵で検証して自分のセッションを作る
3. `accountToken` はパスワードやパスキーを操作するときに `Authorization: Bearer` で送る。期限（既定 10 分）が切れたらログインし直す

Android アプリは `assetlinks.json` に載せると、このドメインのパスキーと保存済みパスワードを Credential Manager で使える。

## アカウント設定

各サービスから `https://auth.example.com/account` にリンクする。開くたびにログインし直し、ログインで受け取ったアカウントトークンで操作する。Cookie は使わない。

## REST

| ID | メソッドとパス | 認証 | 内容 |
| --- | --- | --- | --- |
| 1 | `POST /api/login/password` | 無し | `{username, password, clientId?}` |
| 2 | `POST /api/login/passkey/options` | 無し | PublicKeyCredentialRequestOptionsJSON |
| 3 | `POST /api/login/passkey` | 無し | `{credential, clientId?}`。credential は AuthenticationResponseJSON |
| 4 | `POST /api/authorize` | アカウントトークン | ログイン画面が認可コードを受け取る |
| 5 | `GET /api/account` | アカウントトークン | ユーザー名、パスワードの有無、パスキーの一覧 |
| 6 | `PUT /api/account/password` | アカウントトークン | `{newPassword}`。パスワードが無ければ追加になる |
| 7 | `DELETE /api/account/password` | アカウントトークン | パスキーが無ければ 409 |
| 8 | `POST /api/account/passkeys/options` | アカウントトークン | PublicKeyCredentialCreationOptionsJSON |
| 9 | `POST /api/account/passkeys` | アカウントトークン | `{name, credential}`。credential は RegistrationResponseJSON |
| 10 | `DELETE /api/account/passkeys/{id}` | アカウントトークン | パスワードが無く最後のパスキーなら 409 |

ログイン 1・3 の応答は `{accountToken, accountTokenExpiresAtEpochMillis, loginToken?, loginTokenExpiresAtEpochMillis?}`。
パスワードが違えば 401、送信元の失敗が多すぎれば 429。

## gRPC

[service_account.proto](proto/src/main/proto/serviceaccount/v1/service_account.proto) を参照。
すべての RPC に次の metadata を付ける。

- `x-client-id`: 設定ファイルの `clients[].id`
- `authorization`: `Bearer <クライアントシークレット>`

ログイントークンの `aud` はクライアント ID で、別のクライアントでは通らない。
クレームは `sub`（ユーザー ID）、`preferred_username`、`aud`、`jti`、`token_use`（`login`）。
期限内は同じトークンを何度でも検証できるので、受け取ったらすぐ使い、保存しない。

### 接続ライブラリ

maven.matsudamper.net に公開している。

```kotlin
repositories {
    maven { url = uri("https://maven.matsudamper.net/releases") }
}

dependencies {
    implementation("net.matsudamper.serviceaccount:client:<version>")
}
```

```kotlin
val client = ServiceAccountClient.create(host = "service-account", port = 50051, clientId = "kake-bo", clientSecret = secret)
val response = client.auth.exchangeAuthorizationCode(
    exchangeAuthorizationCodeRequest {
        code = code
        redirectUri = "https://money.example.com/login/callback"
        codeVerifier = codeVerifier
    },
)
```

- `client`: クライアント ID とシークレットを付けて繋ぐ `ServiceAccountClient`。transport に grpc-netty-shaded を含む
- `proto`: 生成したメッセージとコルーチン用のスタブだけ

## 設定

### 環境変数

| ID | 環境変数 | 既定値 | 内容 |
| --- | --- | --- | --- |
| 1 | `SERVICE_ACCOUNT_PUBLIC_URL` | 必須 | ブラウザ・アプリから見た URL（`https://auth.example.com`）。ホスト名がパスキーの RP ID になり、後から変えると登録済みのパスキーが使えなくなる |
| 2 | `SERVICE_ACCOUNT_SIGNING_JWK` | 必須（秘密） | JWT の署名鍵。`generate-signing-key` で作る |
| 3 | `SERVICE_ACCOUNT_CONFIG_FILE` | 必須 | 設定ファイルのパス。[config.example.json](config.example.json) |
| 4 | `SERVICE_ACCOUNT_ISSUER` | `SERVICE_ACCOUNT_PUBLIC_URL` | JWT の `iss` |
| 5 | `SERVICE_ACCOUNT_DATABASE_PATH` | `data/service-account.db`（Docker では `/app/data/service-account.db`） | SQLite のファイル |
| 6 | `SERVICE_ACCOUNT_HTTP_PORT` | `8080` | HTTP |
| 7 | `SERVICE_ACCOUNT_GRPC_PORT` | `50051` | gRPC |
| 8 | `SERVICE_ACCOUNT_TRUST_CF_CONNECTING_IP` | `false` | Cloudflare の後ろに置くときだけ `true`。送信元 IP を `CF-Connecting-IP` から取る |
| 9 | `SERVICE_ACCOUNT_LOGIN_TOKEN_TTL_SECONDS` | `300` | ログイントークンの有効期間 |
| 10 | `SERVICE_ACCOUNT_ACCOUNT_TOKEN_TTL_SECONDS` | `600` | アカウントトークンの有効期間 |
| 11 | `SERVICE_ACCOUNT_MAX_LOGIN_FAILURES` | `10` | 送信元ごとのパスワード失敗の上限 |
| 12 | `SERVICE_ACCOUNT_LOGIN_LOCK_MINUTES` | `15` | 上限に達したときの締め出し時間 |

TLS は終端しない。HTTP は TLS を終端するリバースプロキシの後ろに、gRPC は内部ネットワークに置く。

### 設定ファイル

- `clients[]`: 各サービス。`id`、`secretSha256`（`generate-client-secret` で作る）、`redirectUris`
- `androidApps[]`: このドメインのパスキーとパスワードを使う Android アプリ。`packageName` と署名証明書の `sha256CertFingerprints`（`AA:BB:...`）。`assetlinks.json` とパスキーの origin（`android:apk-key-hash:...`）に使う

## CLI

```sh
service-account serve
service-account add-user <username>       # パスワードは標準入力から
service-account set-password <username>   # パスワードは標準入力から
service-account generate-signing-key
service-account generate-client-secret
```

Docker では次のように実行する。

```sh
docker run --rm -i -v ./data:/app/data ghcr.io/matsudamper/service-account add-user alice
```

`/app/data` は nonroot（UID 65532）で書き込めるようにしておく。

## ビルド

```sh
./gradlew build
./gradlew ktlintFormat
```

native image は JAVA_HOME を GraalVM 25 にして作る。

```sh
./gradlew :server:nativeCompile
docker build -t service-account .
```

## リリース

Actions の Release を手動で実行する。`version` を入力し、`latest` のチェックで GitHub Release の Latest と Docker の `latest` タグを付けるかを選ぶ。
イメージは `ghcr.io/matsudamper/service-account` に、接続ライブラリは maven.matsudamper.net に同じバージョンで公開する。

接続ライブラリの公開には、environment `production` に `MAVEN_MATSUDAMPER_USERNAME` と `MAVEN_MATSUDAMPER_TOKEN` のシークレットが要る。
