package net.matsudamper.serviceaccount.db

import java.time.Instant

enum class PasskeyChallengePurpose {
    Registration,
    Authentication,
}

/**
 * 発行した challenge。使ったら消して、同じものを二度通さない
 */
class PasskeyChallengeRepository(
    private val database: Database,
) {
    /**
     * @param userId 登録ではログイン中のユーザー。ログインでは null
     */
    fun add(
        challenge: String,
        purpose: PasskeyChallengePurpose,
        clientId: String,
        userId: UserId?,
        expiresAt: Instant,
    ) {
        database.transaction { connection ->
            connection.prepareStatement("INSERT INTO passkey_challenges (challenge, purpose, client_id, user_id, expires_at) VALUES (?, ?, ?, ?, ?)").use { statement ->
                statement.setString(1, challenge)
                statement.setString(2, purpose.name)
                statement.setString(3, clientId)
                if (userId == null) statement.setNull(4, java.sql.Types.INTEGER) else statement.setLong(4, userId.value)
                statement.setLong(5, expiresAt.toEpochMilli())
                statement.executeUpdate()
            }
        }
    }

    /**
     * 期限内のものを消し、[purpose]・[clientId]・[userId] も一致していれば true
     */
    fun consume(
        challenge: String,
        purpose: PasskeyChallengePurpose,
        clientId: String,
        userId: UserId?,
        now: Instant,
    ): Boolean =
        database.transaction { connection ->
            connection
                .prepareStatement("DELETE FROM passkey_challenges WHERE challenge = ? RETURNING purpose, client_id, user_id, expires_at")
                .use { statement ->
                    statement.setString(1, challenge)
                    statement.executeQuery().use { result ->
                        if (!result.next()) return@transaction false
                        val storedPurpose = result.getString(1)
                        val storedClientId = result.getString(2)
                        val storedUserId = result.getLong(3).takeUnless { result.wasNull() }
                        val expiresAt = result.getLong(4)
                        storedPurpose == purpose.name &&
                            storedClientId == clientId &&
                            storedUserId == userId?.value &&
                            expiresAt > now.toEpochMilli()
                    }
                }
        }

    fun deleteExpired(now: Instant) {
        database.transaction { connection ->
            connection.prepareStatement("DELETE FROM passkey_challenges WHERE expires_at <= ?").use { statement ->
                statement.setLong(1, now.toEpochMilli())
                statement.executeUpdate()
            }
        }
    }
}
