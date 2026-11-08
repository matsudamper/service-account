package net.matsudamper.serviceaccount.db

import java.time.Instant

/**
 * 送信元とユーザー名ごとに失敗回数を持つ
 */
class LoginFailureRepository(
    private val database: Database,
) {
    /**
     * 送信元の失敗の合計が [maxFailures] 未満なら [username] に 1 足して true を返す。
     * 足したかどうかに関わらず、送信元の記録全体の期限を [expiresAt] に延ばす
     */
    fun reserve(
        clientIp: String,
        username: String,
        maxFailures: Int,
        now: Instant,
        expiresAt: Instant,
    ): Boolean =
        database.transaction { connection ->
            connection.prepareStatement("DELETE FROM login_failures WHERE client_ip = ? AND expires_at <= ?").use { statement ->
                statement.setString(1, clientIp)
                statement.setLong(2, now.toEpochMilli())
                statement.executeUpdate()
            }
            val total =
                connection.prepareStatement("SELECT COALESCE(SUM(failure_count), 0) FROM login_failures WHERE client_ip = ?").use { statement ->
                    statement.setString(1, clientIp)
                    statement.executeQuery().use { result ->
                        result.next()
                        result.getLong(1)
                    }
                }
            val reserved = total < maxFailures
            if (reserved) {
                connection
                    .prepareStatement(
                        """
                        INSERT INTO login_failures (client_ip, username, failure_count, expires_at) VALUES (?, ?, 1, ?)
                        ON CONFLICT (client_ip, username) DO UPDATE SET failure_count = failure_count + 1
                        """.trimIndent(),
                    ).use { statement ->
                        statement.setString(1, clientIp)
                        statement.setString(2, username)
                        statement.setLong(3, expiresAt.toEpochMilli())
                        statement.executeUpdate()
                    }
            }
            connection.prepareStatement("UPDATE login_failures SET expires_at = ? WHERE client_ip = ?").use { statement ->
                statement.setLong(1, expiresAt.toEpochMilli())
                statement.setString(2, clientIp)
                statement.executeUpdate()
            }
            reserved
        }

    fun clear(
        clientIp: String,
        username: String,
    ) {
        database.transaction { connection ->
            connection.prepareStatement("DELETE FROM login_failures WHERE client_ip = ? AND username = ?").use { statement ->
                statement.setString(1, clientIp)
                statement.setString(2, username)
                statement.executeUpdate()
            }
        }
    }

    fun deleteExpired(now: Instant) {
        database.transaction { connection ->
            connection.prepareStatement("DELETE FROM login_failures WHERE expires_at <= ?").use { statement ->
                statement.setLong(1, now.toEpochMilli())
                statement.executeUpdate()
            }
        }
    }
}
