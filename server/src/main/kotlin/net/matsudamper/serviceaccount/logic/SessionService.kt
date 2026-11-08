package net.matsudamper.serviceaccount.logic

import java.time.Clock
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.toJavaDuration
import net.matsudamper.serviceaccount.db.SessionRepository
import net.matsudamper.serviceaccount.db.StoredSession
import net.matsudamper.serviceaccount.db.UserId
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.token.AccessTokenService

/**
 * ログイン状態は、短命な JWT のアクセストークンと、使うたびに作り直すリフレッシュトークンで表す
 */
class SessionService(
    private val sessionRepository: SessionRepository,
    private val userRepository: UserRepository,
    private val accessTokenService: AccessTokenService,
    private val refreshTokenTtl: Duration,
    private val clock: Clock,
) {
    fun create(
        userId: UserId,
        clientId: String,
        sessionName: String,
    ): TokenSet {
        val user = checkNotNull(userRepository.findById(userId)) { "ログインしたユーザーがいない" }
        val sessionId = SecureTokens.random(SESSION_ID_SIZE_BYTES)
        val refreshToken = SecureTokens.random(REFRESH_TOKEN_SIZE_BYTES)
        val now = clock.instant()
        val expiresAt = now.plus(refreshTokenTtl.toJavaDuration())
        sessionRepository.create(
            sessionId = sessionId,
            userId = userId,
            clientId = clientId,
            refreshTokenHash = SecureTokens.sha256(refreshToken),
            name = normalizeSessionName(sessionName) ?: DEFAULT_SESSION_NAME,
            createdAt = now,
            expiresAt = expiresAt,
        )
        val accessToken = accessTokenService.issue(userId = userId, username = user.username, sessionId = sessionId, clientId = clientId)
        return TokenSet(
            accessToken = accessToken.token,
            accessTokenExpiresAt = accessToken.expiresAt,
            refreshToken = refreshToken,
            refreshTokenExpiresAt = expiresAt,
            sessionId = sessionId,
        )
    }

    /**
     * @return 期限切れ・使用済み・別クライアントのものなら null
     */
    fun refresh(
        refreshToken: String,
        clientId: String,
    ): TokenSet? {
        val newRefreshToken = SecureTokens.random(REFRESH_TOKEN_SIZE_BYTES)
        val now = clock.instant()
        val expiresAt = now.plus(refreshTokenTtl.toJavaDuration())
        val session =
            sessionRepository.rotate(
                refreshTokenHash = SecureTokens.sha256(refreshToken),
                clientId = clientId,
                newRefreshTokenHash = SecureTokens.sha256(newRefreshToken),
                now = now,
                expiresAt = expiresAt,
            ) ?: return null
        val user = userRepository.findById(session.userId) ?: return null
        val accessToken = accessTokenService.issue(userId = user.id, username = user.username, sessionId = session.sessionId, clientId = clientId)
        return TokenSet(
            accessToken = accessToken.token,
            accessTokenExpiresAt = accessToken.expiresAt,
            refreshToken = newRefreshToken,
            refreshTokenExpiresAt = expiresAt,
            sessionId = session.sessionId,
        )
    }

    fun logout(
        refreshToken: String,
        clientId: String,
    ) {
        sessionRepository.deleteByRefreshTokenHash(refreshTokenHash = SecureTokens.sha256(refreshToken), clientId = clientId)
    }

    /**
     * JWT の検証に加えて、セッションが消されていないかを見る
     */
    fun authenticate(
        accessToken: String,
        clientId: String,
    ): AuthenticatedUser? {
        val claims = accessTokenService.verify(token = accessToken, clientId = clientId) ?: return null
        val session = sessionRepository.find(sessionId = claims.sessionId, now = clock.instant()) ?: return null
        if (session.userId != claims.userId) return null
        return AuthenticatedUser(userId = claims.userId, username = claims.username, sessionId = claims.sessionId)
    }

    fun sessions(userId: UserId): List<StoredSession> = sessionRepository.sessions(userId = userId, now = clock.instant())

    fun delete(
        userId: UserId,
        sessionId: String,
    ): Boolean = sessionRepository.delete(userId = userId, sessionId = sessionId)

    fun rename(
        userId: UserId,
        sessionId: String,
        name: String,
    ): RenameResult {
        val normalized = normalizeSessionName(name) ?: return RenameResult.InvalidName
        return if (sessionRepository.rename(userId = userId, sessionId = sessionId, name = normalized)) RenameResult.Success else RenameResult.NotFound
    }

    fun deleteExpired() {
        sessionRepository.deleteExpired(clock.instant())
    }

    private fun normalizeSessionName(name: String): String? {
        val trimmed = name.trim()
        if (trimmed.isEmpty() || trimmed.codePointCount(0, trimmed.length) > MAX_SESSION_NAME_LENGTH) return null
        return trimmed
    }

    enum class RenameResult {
        Success,
        NotFound,
        InvalidName,
    }

    private companion object {
        const val SESSION_ID_SIZE_BYTES = 16
        const val REFRESH_TOKEN_SIZE_BYTES = 32
        const val MAX_SESSION_NAME_LENGTH = 64
        const val DEFAULT_SESSION_NAME = "unnamed"
    }
}

class TokenSet(
    val accessToken: String,
    val accessTokenExpiresAt: Instant,
    val refreshToken: String,
    val refreshTokenExpiresAt: Instant,
    val sessionId: String,
)

data class AuthenticatedUser(
    val userId: UserId,
    val username: String,
    val sessionId: String,
)
