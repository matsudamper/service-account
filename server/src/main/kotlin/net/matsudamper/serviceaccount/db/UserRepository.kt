package net.matsudamper.serviceaccount.db

import java.sql.Connection
import java.time.Instant

@JvmInline
value class UserId(
    val value: Long,
)

data class User(
    val id: UserId,
    val username: String,
    val passkeyUserHandle: String,
)

data class StoredPassword(
    val userId: UserId,
    val hashType: String,
    val hash: String,
)

class UserRepository(
    private val database: Database,
) {
    /**
     * @return 既に同じ名前のユーザーがいれば null
     */
    fun add(
        username: String,
        passkeyUserHandle: String,
        passwordHashType: String,
        passwordHash: String,
        createdAt: Instant,
    ): UserId? =
        database.transaction { connection ->
            val userId =
                connection
                    .prepareStatement("INSERT INTO users (username, passkey_user_handle, created_at) VALUES (?, ?, ?) ON CONFLICT (username) DO NOTHING RETURNING user_id")
                    .use { statement ->
                        statement.setString(1, username)
                        statement.setString(2, passkeyUserHandle)
                        statement.setLong(3, createdAt.toEpochMilli())
                        statement.executeQuery().use { result -> if (result.next()) UserId(result.getLong(1)) else null }
                    } ?: return@transaction null
            upsertPassword(connection, userId, passwordHashType, passwordHash, createdAt)
            userId
        }

    fun findById(id: UserId): User? =
        database.read { connection ->
            connection.prepareStatement("SELECT user_id, username, passkey_user_handle FROM users WHERE user_id = ?").use { statement ->
                statement.setLong(1, id.value)
                statement.executeQuery().use { result -> if (result.next()) result.toUser() else null }
            }
        }

    fun findByUsername(username: String): User? =
        database.read { connection ->
            connection.prepareStatement("SELECT user_id, username, passkey_user_handle FROM users WHERE username = ?").use { statement ->
                statement.setString(1, username)
                statement.executeQuery().use { result -> if (result.next()) result.toUser() else null }
            }
        }

    fun findPasswordByUsername(username: String): StoredPassword? =
        database.read { connection ->
            connection
                .prepareStatement(
                    """
                    SELECT p.user_id, p.password_hash_type, p.password_hash
                    FROM user_passwords p JOIN users u ON u.user_id = p.user_id
                    WHERE u.username = ?
                    """.trimIndent(),
                ).use { statement ->
                    statement.setString(1, username)
                    statement.executeQuery().use { result ->
                        if (result.next()) {
                            StoredPassword(userId = UserId(result.getLong(1)), hashType = result.getString(2), hash = result.getString(3))
                        } else {
                            null
                        }
                    }
                }
        }

    fun hasPassword(id: UserId): Boolean =
        database.read { connection ->
            connection.prepareStatement("SELECT 1 FROM user_passwords WHERE user_id = ?").use { statement ->
                statement.setLong(1, id.value)
                statement.executeQuery().use { it.next() }
            }
        }

    fun setPassword(
        id: UserId,
        hashType: String,
        hash: String,
        updatedAt: Instant,
    ) {
        database.transaction { connection -> upsertPassword(connection, id, hashType, hash, updatedAt) }
    }

    /**
     * パスキーが 1 つも無ければ消さない。判定と削除の間にパスキーを消されないよう 1 文で行う
     *
     * @return 消したら true
     */
    fun deletePasswordIfPasskeyExists(id: UserId): Boolean =
        database.transaction { connection ->
            connection
                .prepareStatement("DELETE FROM user_passwords WHERE user_id = ? AND EXISTS (SELECT 1 FROM passkeys WHERE user_id = ?)")
                .use { statement ->
                    statement.setLong(1, id.value)
                    statement.setLong(2, id.value)
                    statement.executeUpdate() > 0
                }
        }

    private fun upsertPassword(
        connection: Connection,
        id: UserId,
        hashType: String,
        hash: String,
        updatedAt: Instant,
    ) {
        connection
            .prepareStatement(
                """
                INSERT INTO user_passwords (user_id, password_hash_type, password_hash, updated_at) VALUES (?, ?, ?, ?)
                ON CONFLICT (user_id) DO UPDATE SET password_hash_type = excluded.password_hash_type, password_hash = excluded.password_hash, updated_at = excluded.updated_at
                """.trimIndent(),
            ).use { statement ->
                statement.setLong(1, id.value)
                statement.setString(2, hashType)
                statement.setString(3, hash)
                statement.setLong(4, updatedAt.toEpochMilli())
                statement.executeUpdate()
            }
    }

    private fun java.sql.ResultSet.toUser(): User =
        User(
            id = UserId(getLong(1)),
            username = getString(2),
            passkeyUserHandle = getString(3),
        )
}
