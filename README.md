# service-account

複数のサービスのログインをまとめる認証サービス。各サービスのバックエンドから gRPC で呼び出す。

- ログイン: パスワード / パスキー（WebAuthn）
- ログイン状態: ES256 で署名した JWT のアクセストークン（短命）と、使うたびに作り直すリフレッシュトークン
- アカウント操作: パスワードの変更・追加・削除、パスキーの登録・一覧・削除、セッションの一覧・削除・名前変更
- ユーザー登録: サーバー上の CLI からだけ行う
- 保存先: SQLite
- 配布: GraalVM の native image を distroless に載せた Docker イメージ

API は [service_account.proto](proto/src/main/proto/serviceaccount/v1/service_account.proto) を参照。
呼び出し側は `:proto` モジュール（Kotlin のコルーチン用スタブを含む）を使える。

## 呼び出し元の認証

呼び出し元のサービスはクライアントとして設定ファイルに登録し、すべての RPC に次の metadata を付ける。

- `x-client-id`: 設定ファイルの `id`
- `authorization`: `Bearer <クライアントシークレット>`

アクセストークンの `aud` とリフレッシュトークンは発行を依頼したクライアントに紐づき、別のクライアントからは使えない。
パスキーは RP ID に紐づくので、クライアントの `passkey.rpId` で登録したものだけがそのクライアントからのログインに使える。

## アクセストークンの検証

- `AuthService.VerifyAccessToken`: 署名・期限・`aud` に加え、セッションが消されていないかも見る
- `AuthService.GetJwks` の公開鍵で呼び出し側が検証する: 速いが、期限内はセッションの削除が反映されない

クレームは `sub`（ユーザー ID）、`preferred_username`、`sid`（セッション ID）、`aud`（クライアント ID）。

## 設定

| ID | 環境変数 | 既定値 | 内容 |
| --- | --- | --- | --- |
| 1 | `SERVICE_ACCOUNT_ISSUER` | 必須 | JWT の `iss` |
| 2 | `SERVICE_ACCOUNT_SIGNING_JWK` | 必須 | 署名鍵。`generate-signing-key` で作る |
| 3 | `SERVICE_ACCOUNT_CLIENTS_FILE` | 必須 | クライアントの設定ファイル。[clients.example.json](clients.example.json) |
| 4 | `SERVICE_ACCOUNT_DATABASE_PATH` | `data/service-account.db`（Docker では `/app/data/service-account.db`） | SQLite のファイル |
| 5 | `SERVICE_ACCOUNT_GRPC_PORT` | `50051` | 待ち受けるポート |
| 6 | `SERVICE_ACCOUNT_ACCESS_TOKEN_TTL_SECONDS` | `600` | アクセストークンの有効期間 |
| 7 | `SERVICE_ACCOUNT_REFRESH_TOKEN_TTL_DAYS` | `30` | リフレッシュトークンの有効期間。使うたびに延びる |
| 8 | `SERVICE_ACCOUNT_MAX_LOGIN_FAILURES` | `10` | 送信元ごとのパスワード失敗の上限 |
| 9 | `SERVICE_ACCOUNT_LOGIN_LOCK_MINUTES` | `15` | 上限に達したときの締め出し時間 |

TLS は終端しない。内部ネットワークか、TLS を終端するリバースプロキシの後ろに置く。

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
イメージは `ghcr.io/matsudamper/service-account` に公開する。
