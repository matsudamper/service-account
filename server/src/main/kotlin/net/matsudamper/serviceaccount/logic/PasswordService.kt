package net.matsudamper.serviceaccount.logic

import java.time.Clock
import kotlin.time.Duration
import kotlin.time.toJavaDuration
import net.matsudamper.serviceaccount.db.LoginFailureRepository
import net.matsudamper.serviceaccount.db.UserId
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.password.PasswordHashType
import net.matsudamper.serviceaccount.password.PasswordPolicy
import net.matsudamper.serviceaccount.password.PasswordViolations

class PasswordService(
    private val userRepository: UserRepository,
    private val loginFailureRepository: LoginFailureRepository,
    private val maxLoginFailures: Int,
    private val lockDuration: Duration,
    private val clock: Clock,
) {
    /**
     * ユーザーがいなくても同じだけ計算し、応答時間で名前の有無を分からなくする。
     * 遅延生成すると最初の 1 回だけ遅くなるので最初から初期化しておく
     */
    private val dummyPasswordHash: String = checkNotNull(PasswordHashType.Current.encoder.encode("dummy-password"))

    /**
     * 照合の前に失敗を 1 回分先に数える。
     * 照合の後に数えると、同時に送られたリクエストが数える前の判定をすり抜けて上限を超えて照合できる
     */
    fun login(
        username: String,
        password: String,
        clientIp: String,
    ): PasswordLoginResult {
        val trimmedUsername = username.trim()
        val now = clock.instant()
        val reserved =
            loginFailureRepository.reserve(
                clientIp = clientIp,
                username = trimmedUsername,
                maxFailures = maxLoginFailures,
                now = now,
                expiresAt = now.plus(lockDuration.toJavaDuration()),
            )
        if (!reserved) return PasswordLoginResult.TooManyAttempts

        val userId = verify(trimmedUsername, password) ?: return PasswordLoginResult.NotAccepted
        // 自分のアカウントで成功して他のアカウントへの失敗まで消せないよう、成功したユーザー名の分だけ消す
        loginFailureRepository.clear(clientIp = clientIp, username = trimmedUsername)
        return PasswordLoginResult.Success(userId)
    }

    fun hasPassword(userId: UserId): Boolean = userRepository.hasPassword(userId)

    fun change(
        userId: UserId,
        newPassword: String,
    ): PasswordViolations {
        val violations = PasswordPolicy.validate(newPassword)
        if (!violations.isValid) return violations
        userRepository.setPassword(
            id = userId,
            hashType = PasswordHashType.Current.dbValue,
            hash = hash(newPassword),
            updatedAt = clock.instant(),
        )
        return violations
    }

    fun delete(userId: UserId): DeletePasswordResult =
        when {
            userRepository.deletePasswordIfPasskeyExists(userId) -> DeletePasswordResult.Success
            userRepository.hasPassword(userId) -> DeletePasswordResult.NoPasskey
            else -> DeletePasswordResult.Success
        }

    fun deleteExpiredLoginFailures() {
        loginFailureRepository.deleteExpired(clock.instant())
    }

    private fun verify(
        username: String,
        password: String,
    ): UserId? {
        val stored = userRepository.findPasswordByUsername(username)
        if (stored == null) {
            PasswordHashType.Current.encoder.matches(password, dummyPasswordHash)
            return null
        }
        // 対応していない値はパスワード違いと区別できるよう落とす
        val hashType = checkNotNull(PasswordHashType.fromDbValue(stored.hashType)) { "対応していない password_hash_type: ${stored.hashType}" }
        return stored.userId.takeIf { hashType.encoder.matches(password, stored.hash) }
    }

    enum class DeletePasswordResult {
        Success,
        NoPasskey,
    }

    companion object {
        fun hash(password: String): String = checkNotNull(PasswordHashType.Current.encoder.encode(password))
    }
}

sealed interface PasswordLoginResult {
    data class Success(
        val userId: UserId,
    ) : PasswordLoginResult

    data object NotAccepted : PasswordLoginResult

    data object TooManyAttempts : PasswordLoginResult
}
