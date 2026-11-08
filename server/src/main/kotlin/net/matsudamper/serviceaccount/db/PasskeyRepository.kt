package net.matsudamper.serviceaccount.db

import java.sql.ResultSet
import java.time.Instant

data class StoredPasskey(
    val credentialId: String,
    val userId: UserId,
    val rpId: String,
    val attestedCredentialData: ByteArray,
    val signCount: Long,
)

data class PasskeySummary(
    val credentialId: String,
    val name: String,
    val rpId: String,
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
        rpId: String,
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
                    INSERT INTO passkeys (credential_id, user_id, rp_id, attested_credential_data, sign_count, name, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (credential_id) DO NOTHING
                    """.trimIndent(),
                ).use { statement ->
                    statement.setString(1, credentialId)
                    statement.setLong(2, userId.value)
                    statement.setString(3, rpId)
                    statement.setBytes(4, attestedCredentialData)
                    statement.setLong(5, signCount)
                    statement.setString(6, name)
                    statement.setLong(7, createdAt.toEpochMilli())
                    statement.executeUpdate() > 0
                }
        }

    fun find(
        credentialId: String,
        rpId: String,
    ): StoredPasskey? =
        database.read { connection ->
            connection
                .prepareStatement("SELECT credential_id, user_id, rp_id, attested_credential_data, sign_count FROM passkeys WHERE credential_id = ? AND rp_id = ?")
                .use { statement ->
                    statement.setString(1, credentialId)
                    statement.setString(2, rpId)
                    statement.executeQuery().use { result ->
                        if (result.next()) {
                            StoredPasskey(
                                credentialId = result.getString(1),
                                userId = UserId(result.getLong(2)),
                                rpId = result.getString(3),
                                attestedCredentialData = result.getBytes(4),
                                signCount = result.getLong(5),
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
                .prepareStatement("SELECT credential_id, name, rp_id, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY created_at")
                .use { statement ->
                    statement.setLong(1, userId.value)
                    statement.executeQuery().use { result ->
                        buildList {
                            while (result.next()) add(result.toSummary())
                        }
                    }
                }
        }

    fun credentialIds(
        userId: UserId,
        rpId: String,
    ): List<String> =
        database.read { connection ->
            connection.prepareStatement("SELECT credential_id FROM passkeys WHERE user_id = ? AND rp_id = ?").use { statement ->
                statement.setLong(1, userId.value)
                statement.setString(2, rpId)
                statement.executeQuery().use { result ->
                    buildList {
                        while (result.next()) add(result.getString(1))
                    }
                }
            }
        }

    fun updateSignCount(
        credentialId: String,
        signCount: Long,
        usedAt: Instant,
    ) {
        database.transaction { connection ->
            connection.prepareStatement("UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE credential_id = ?").use { statement ->
                statement.setLong(1, signCount)
                statement.setLong(2, usedAt.toEpochMilli())
                statement.setString(3, credentialId)
                statement.executeUpdate()
            }
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
            rpId = getString(3),
            createdAt = Instant.ofEpochMilli(getLong(4)),
            lastUsedAt = getLong(5).takeUnless { wasNull() }?.let(Instant::ofEpochMilli),
        )
}
