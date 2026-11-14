package net.matsudamper.serviceaccount.db

import java.sql.ResultSet
import java.time.Instant

data class StoredPasskey(
    val credentialId: String,
    val userId: UserId,
    val attestedCredentialData: ByteArray,
    val signCount: Long,
)

data class PasskeySummary(
    val credentialId: String,
    val name: String,
    val createdAt: Instant,
    val lastUsedAt: Instant?,
)

enum class PasskeyDeleteResult {
    Success,
    NotFound,
    LastLoginMethod,
}

class PasskeyRepository(
    private val database: Database,
) {
    /**
     * @return 同じ credential ID が登録済みなら false
     */
    fun add(
        userId: UserId,
        credentialId: String,
        attestedCredentialData: ByteArray,
        signCount: Long,
        name: String,
        createdAt: Instant,
    ): Boolean =
        database.transaction { connection ->
            connection
                .prepareStatement(
                    """
                    INSERT INTO passkeys (credential_id, user_id, attested_credential_data, sign_count, name, created_at)
                    VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (credential_id) DO NOTHING
                    """.trimIndent(),
                ).use { statement ->
                    statement.setString(1, credentialId)
                    statement.setLong(2, userId.value)
                    statement.setBytes(3, attestedCredentialData)
                    statement.setLong(4, signCount)
                    statement.setString(5, name)
                    statement.setLong(6, createdAt.toEpochMilli())
                    statement.executeUpdate() > 0
                }
        }

    fun find(credentialId: String): StoredPasskey? =
        database.read { connection ->
            connection
                .prepareStatement("SELECT credential_id, user_id, attested_credential_data, sign_count FROM passkeys WHERE credential_id = ?")
                .use { statement ->
                    statement.setString(1, credentialId)
                    statement.executeQuery().use { result ->
                        if (result.next()) {
                            StoredPasskey(
                                credentialId = result.getString(1),
                                userId = UserId(result.getLong(2)),
                                attestedCredentialData = result.getBytes(3),
                                signCount = result.getLong(4),
                            )
                        } else {
                            null
                        }
                    }
                }
        }

    fun passkeys(userId: UserId): List<PasskeySummary> =
        database.read { connection ->
            connection
                .prepareStatement("SELECT credential_id, name, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY created_at")
                .use { statement ->
                    statement.setLong(1, userId.value)
                    statement.executeQuery().use { result ->
                        buildList {
                            while (result.next()) add(result.toSummary())
                        }
                    }
                }
        }

    fun credentialIds(userId: UserId): List<String> =
        database.read { connection ->
            connection.prepareStatement("SELECT credential_id FROM passkeys WHERE user_id = ?").use { statement ->
                statement.setLong(1, userId.value)
                statement.executeQuery().use { result ->
                    buildList {
                        while (result.next()) add(result.getString(1))
                    }
                }
            }
        }

    /**
     * 同じパスキーのログインが同時に通ったときに回数を戻さないよう、検証に使った [expectedSignCount] のままのときだけ更新する
     *
     * @return 更新したら true。他のログインが先に更新していたら false
     */
    fun updateSignCount(
        credentialId: String,
        expectedSignCount: Long,
        signCount: Long,
        usedAt: Instant,
    ): Boolean =
        database.transaction { connection ->
            connection.prepareStatement("UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE credential_id = ? AND sign_count = ?").use { statement ->
                statement.setLong(1, signCount)
                statement.setLong(2, usedAt.toEpochMilli())
                statement.setString(3, credentialId)
                statement.setLong(4, expectedSignCount)
                statement.executeUpdate() > 0
            }
        }

    /**
     * パスワードが無いときに最後のパスキーを消すとログインできなくなるので消さない
     */
    fun delete(
        userId: UserId,
        credentialId: String,
    ): PasskeyDeleteResult =
        database.transaction { connection ->
            val deleted =
                connection
                    .prepareStatement(
                        """
                        DELETE FROM passkeys WHERE user_id = ? AND credential_id = ?
                        AND (
                            EXISTS (SELECT 1 FROM user_passwords WHERE user_id = ?)
                            OR (SELECT COUNT(*) FROM passkeys WHERE user_id = ?) > 1
                        )
                        """.trimIndent(),
                    ).use { statement ->
                        statement.setLong(1, userId.value)
                        statement.setString(2, credentialId)
                        statement.setLong(3, userId.value)
                        statement.setLong(4, userId.value)
                        statement.executeUpdate() > 0
                    }
            if (deleted) return@transaction PasskeyDeleteResult.Success

            val exists =
                connection.prepareStatement("SELECT 1 FROM passkeys WHERE user_id = ? AND credential_id = ?").use { statement ->
                    statement.setLong(1, userId.value)
                    statement.setString(2, credentialId)
                    statement.executeQuery().use { it.next() }
                }
            if (exists) PasskeyDeleteResult.LastLoginMethod else PasskeyDeleteResult.NotFound
        }

    private fun ResultSet.toSummary(): PasskeySummary =
        PasskeySummary(
            credentialId = getString(1),
            name = getString(2),
            createdAt = Instant.ofEpochMilli(getLong(3)),
            lastUsedAt = getLong(4).takeUnless { wasNull() }?.let(Instant::ofEpochMilli),
        )
}
