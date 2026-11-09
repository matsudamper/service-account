package net.matsudamper.serviceaccount

import java.io.File
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

class ServerEnv(
    private val env: Map<String, String> = System.getenv(),
) {
    val databasePath: String = env["SERVICE_ACCOUNT_DATABASE_PATH"] ?: "data/service-account.db"

    val grpcPort: Int = env["SERVICE_ACCOUNT_GRPC_PORT"]?.toInt() ?: 50051

    /**
     * JWT の iss
     */
    val issuer: String get() = required("SERVICE_ACCOUNT_ISSUER")

    /**
     * 秘密鍵を含む P-256 の EC JWK。`generate-signing-key` で作る
     */
    val signingJwk: String get() = required("SERVICE_ACCOUNT_SIGNING_JWK")

    val clientsJson: String get() = File(required("SERVICE_ACCOUNT_CLIENTS_FILE")).readText()

    /**
     * 呼び出し元はログイントークンを受け取ってすぐ検証するので短くてよい。サーバー間の時計のずれの分だけ余裕を持たせる
     */
    val loginTokenTtl: Duration = env["SERVICE_ACCOUNT_LOGIN_TOKEN_TTL_SECONDS"]?.toLong()?.seconds ?: 5.minutes

    val maxLoginFailures: Int = env["SERVICE_ACCOUNT_MAX_LOGIN_FAILURES"]?.toInt() ?: 10

    val loginLockDuration: Duration = env["SERVICE_ACCOUNT_LOGIN_LOCK_MINUTES"]?.toLong()?.minutes ?: 15.minutes

    private fun required(name: String): String = env[name]?.takeIf { it.isNotBlank() } ?: error("環境変数 $name が無い")
}
