package net.matsudamper.serviceaccount

import java.io.File
import java.net.URI
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

class ServerEnv(
    private val env: Map<String, String> = System.getenv(),
) {
    val databasePath: String = env["SERVICE_ACCOUNT_DATABASE_PATH"] ?: "data/service-account.db"

    /**
     * 各サービスのバックエンドが呼ぶ gRPC
     */
    val grpcPort: Int = env["SERVICE_ACCOUNT_GRPC_PORT"]?.toInt() ?: 50051

    /**
     * ログイン画面と REST
     */
    val httpPort: Int = env["SERVICE_ACCOUNT_HTTP_PORT"]?.toInt() ?: 8080

    /**
     * ブラウザやアプリから見たこのサービスの URL。`https://auth.example.com` の形。
     * ホスト名がパスキーの RP ID になり、後から変えると登録済みのパスキーが使えなくなる
     */
    val publicUrl: URI get() = URI(required("SERVICE_ACCOUNT_PUBLIC_URL").trimEnd('/'))

    /**
     * JWT の iss
     */
    val issuer: String get() = env["SERVICE_ACCOUNT_ISSUER"]?.takeIf { it.isNotBlank() } ?: publicUrl.toString()

    /**
     * 秘密鍵を含む P-256 の EC JWK。`generate-signing-key` で作る
     */
    val signingJwk: String get() = required("SERVICE_ACCOUNT_SIGNING_JWK")

    val configJson: String get() = File(required("SERVICE_ACCOUNT_CONFIG_FILE")).readText()

    /**
     * 各サービスはログイントークンを受け取ってすぐ検証するので短くてよい。サーバー間の時計のずれの分だけ余裕を持たせる
     */
    val loginTokenTtl: Duration = env["SERVICE_ACCOUNT_LOGIN_TOKEN_TTL_SECONDS"]?.toLong()?.seconds ?: 5.minutes

    /**
     * ログインしてからパスワードやパスキーを操作できる時間
     */
    val accountTokenTtl: Duration = env["SERVICE_ACCOUNT_ACCOUNT_TOKEN_TTL_SECONDS"]?.toLong()?.seconds ?: 10.minutes

    val maxLoginFailures: Int = env["SERVICE_ACCOUNT_MAX_LOGIN_FAILURES"]?.toInt() ?: 10

    val loginLockDuration: Duration = env["SERVICE_ACCOUNT_LOGIN_LOCK_MINUTES"]?.toLong()?.minutes ?: 15.minutes

    /**
     * Cloudflare の後ろに置くときだけ true にする。それ以外で true にすると送信元 IP を偽れる
     */
    val trustCfConnectingIp: Boolean = env["SERVICE_ACCOUNT_TRUST_CF_CONNECTING_IP"]?.toBooleanStrict() ?: false

    private fun required(name: String): String = env[name]?.takeIf { it.isNotBlank() } ?: error("環境変数 $name が無い")
}
