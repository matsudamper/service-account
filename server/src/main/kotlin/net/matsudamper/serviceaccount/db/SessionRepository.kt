package net.matsudamper.serviceaccount.db

import java.sql.ResultSet
import java.time.Instant

data class StoredSession(
    val sessionId: String,
    val userId: UserId,
    val clientId: String,
    val name: String,
    val createdAt: Instant,
    val lastUsedAt: Instant,
    val expiresAt: Instant,
)

/**
 * 保存先が漏れても使えないよう、リフレッシュトークンはハッシュで受け取る
 */
class SessionRepository(
    private val database: Database,
) {
    fun create(
        sessionId: String,
        userId: UserId,
        clientId: String,
        refreshTokenHash: String,
        name: String,
        createdAt: Instant,
        expiresAt: Instant,
    ) {
        database.transaction { connection ->
            connection
                .prepareStatement(
                    """
                    INSERT INTO sessions (session_id, user_id, client_id, refresh_token_hash, name, created_at, last_used_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """.trimIndent(),
                ).use { statement ->
                    statement.setString(1, sessionId)
                    statement.setLong(2, userId.value)
                    statement.setString(3, clientId)
                    statement.setString(4, refreshTokenHash)
                    statement.setString(5, name)
                    statement.setLong(6, createdAt.toEpochMilli())
                    statement.setLong(7, createdAt.toEpochMilli())
                    statement.setLong(8, expiresAt.toEpochMilli())
                    statement.executeUpdate()
                }
        }
    }

    /**
     * 同じリフレッシュトークンを同時に送られても 1 つしか通らないよう、照合と差し替えを 1 文で行う
     *
     * @return 差し替えたセッション。期限切れ・不一致なら null
     */
    fun rotate(
        refreshTokenHash: String,
        clientId: String,
        newRefreshTokenHash: String,
        now: Instant,
        expiresAt: Instant,
    ): StoredSession? =
        database.transaction { connection ->
            connection
                .prepareStatement(
                    """
                    UPDATE sessions SET refresh_token_hash = ?, last_used_at = ?, expires_at = ?
                    WHERE refresh_token_hash = ? AND client_id = ? AND expires_at > ?
                    RETURNING $COLUMNS
                    """.trimIndent(),
                ).use { statement ->
                    statement.setString(1, newRefreshTokenHash)
                    statement.setLong(2, now.toEpochMilli())
                    statement.setLong(3, expiresAt.toEpochMilli())
                    statement.setString(4, refreshTokenHash)
                    statement.setString(5, clientId)
                    statement.setLong(6, now.toEpochMilli())
                    statement.executeQuery().use { result -> if (result.next()) result.toSession() else null }
                }
        }

    fun find(
        sessionId: String,
        now: Instant,
    ): StoredSession? =
        database.read { connection ->
            connection.prepareStatement("SELECT $COLUMNS FROM sessions WHERE session_id = ? AND expires_at > ?").use { statement ->
                statement.setString(1, sessionId)
                statement.setLong(2, now.toEpochMilli())
                statement.executeQuery().use { result -> if (result.next()) result.toSession() else null }
            }
        }

    fun sessions(
        userId: UserId,
        now: Instant,
    ): List<StoredSession> =
        database.read { connection ->
            connection.prepareStatement("SELECT $COLUMNS FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY last_used_at DESC").use { statement ->
                statement.setLong(1, userId.value)
                statement.setLong(2, now.toEpochMilli())
                statement.executeQuery().use { result ->
                    buildList {
                        while (result.next()) add(result.toSession())
                    }
                }
            }
        }

    fun deleteByRefreshTokenHash(
        refreshTokenHash: String,
        clientId: String,
    ) {
        database.transaction { connection ->
            connection.prepareStatement("DELETE FROM sessions WHERE refresh_token_hash = ? AND client_id = ?").use { statement ->
                statement.setString(1, refreshTokenHash)
                statement.setString(2, clientId)
                statement.executeUpdate()
            }
        }
    }

    /**
     * @return 消したら true
     */
    fun delete(
        userId: UserId,
        sessionId: String,
    ): Boolean =
        database.transaction { connection ->
            connection.prepareStatement("DELETE FROM sessions WHERE user_id = ? AND session_id = ?").use { statement ->
                statement.setLong(1, userId.value)
                statement.setString(2, sessionId)
                statement.executeUpdate() > 0
            }
        }

    /**
     * @return 変えたら true
     */
    fun rename(
        userId: UserId,
        sessionId: String,
        name: String,
    ): Boolean =
        database.transaction { connection ->
            connection.prepareStatement("UPDATE sessions SET name = ? WHERE user_id = ? AND session_id = ?").use { statement ->
                statement.setString(1, name)
                statement.setLong(2, userId.value)
                statement.setString(3, sessionId)
                statement.executeUpdate() > 0
            }
        }

    fun deleteExpired(now: Instant) {
        database.transaction { connection ->
            connection.prepareStatement("DELETE FROM sessions WHERE expires_at <= ?").use { statement ->
                statement.setLong(1, now.toEpochMilli())
                statement.executeUpdate()
            }
        }
    }

    private fun ResultSet.toSession(): StoredSession =
        StoredSession(
            sessionId = getString(1),
            userId = UserId(getLong(2)),
            clientId = getString(3),
            name = getString(4),
            createdAt = Instant.ofEpochMilli(getLong(5)),
            lastUsedAt = Instant.ofEpochMilli(getLong(6)),
            expiresAt = Instant.ofEpochMilli(getLong(7)),
        )

    private companion object {
        const val COLUMNS = "session_id, user_id, client_id, name, created_at, last_used_at, expires_at"
    }
}
