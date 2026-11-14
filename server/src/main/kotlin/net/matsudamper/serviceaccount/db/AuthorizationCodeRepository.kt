package net.matsudamper.serviceaccount.db

import java.time.Instant

data class StoredAuthorizationCode(
    val clientId: String,
    val redirectUri: String,
    val codeChallenge: String,
    val userId: UserId,
    val expiresAt: Instant,
)

/**
 * 認可コードはハッシュで受け取る。保存先が漏れても交換に使えない
 */
class AuthorizationCodeRepository(
    private val database: Database,
) {
    fun add(
        codeHash: String,
        code: StoredAuthorizationCode,
    ) {
        database.transaction { connection ->
            connection
                .prepareStatement(
                    "INSERT INTO authorization_codes (code_hash, client_id, redirect_uri, code_challenge, user_id, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                ).use { statement ->
                    statement.setString(1, codeHash)
                    statement.setString(2, code.clientId)
                    statement.setString(3, code.redirectUri)
                    statement.setString(4, code.codeChallenge)
                    statement.setLong(5, code.userId.value)
                    statement.setLong(6, code.expiresAt.toEpochMilli())
                    statement.executeUpdate()
                }
        }
    }

    /**
     * 照合に失敗しても消す。1 つのコードを何度も試させない
     */
    fun consume(codeHash: String): StoredAuthorizationCode? =
        database.transaction { connection ->
            connection
                .prepareStatement("DELETE FROM authorization_codes WHERE code_hash = ? RETURNING client_id, redirect_uri, code_challenge, user_id, expires_at")
                .use { statement ->
                    statement.setString(1, codeHash)
                    statement.executeQuery().use { result ->
                        if (!result.next()) return@transaction null
                        StoredAuthorizationCode(
                            clientId = result.getString(1),
                            redirectUri = result.getString(2),
                            codeChallenge = result.getString(3),
                            userId = UserId(result.getLong(4)),
                            expiresAt = Instant.ofEpochMilli(result.getLong(5)),
                        )
                    }
                }
        }

    fun deleteExpired(now: Instant) {
        database.transaction { connection ->
            connection.prepareStatement("DELETE FROM authorization_codes WHERE expires_at <= ?").use { statement ->
                statement.setLong(1, now.toEpochMilli())
                statement.executeUpdate()
            }
        }
    }
}
