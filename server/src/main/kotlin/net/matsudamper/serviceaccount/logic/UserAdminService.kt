package net.matsudamper.serviceaccount.logic

import java.time.Clock
import net.matsudamper.serviceaccount.db.UserId
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.password.PasswordHashType
import net.matsudamper.serviceaccount.password.PasswordPolicy
import net.matsudamper.serviceaccount.password.PasswordViolations

/**
 * ユーザーの登録はサーバー上の CLI からだけ行う。gRPC には出さない
 */
class UserAdminService(
    private val userRepository: UserRepository,
    private val clock: Clock,
) {
    fun addUser(
        username: String,
        password: String,
    ): AddUserResult {
        val trimmedUsername = username.trim()
        if (!USERNAME_PATTERN.matches(trimmedUsername)) return AddUserResult.InvalidUsername
        val violations = PasswordPolicy.validate(password)
        if (!violations.isValid) return AddUserResult.InvalidPassword(violations)

        val userId =
            userRepository.add(
                username = trimmedUsername,
                passkeyUserHandle = SecureTokens.random(USER_HANDLE_SIZE_BYTES),
                passwordHashType = PasswordHashType.Current.dbValue,
                passwordHash = PasswordService.hash(password),
                createdAt = clock.instant(),
            ) ?: return AddUserResult.AlreadyExists
        return AddUserResult.Success(userId)
    }

    fun replacePassword(
        username: String,
        password: String,
    ): ReplacePasswordResult {
        val user = userRepository.findByUsername(username.trim()) ?: return ReplacePasswordResult.UserNotFound
        val violations = PasswordPolicy.validate(password)
        if (!violations.isValid) return ReplacePasswordResult.InvalidPassword(violations)
        userRepository.setPassword(id = user.id, hashType = PasswordHashType.Current.dbValue, hash = PasswordService.hash(password), updatedAt = clock.instant())
        return ReplacePasswordResult.Success
    }

    sealed interface AddUserResult {
        data class Success(
            val userId: UserId,
        ) : AddUserResult

        data object InvalidUsername : AddUserResult

        data class InvalidPassword(
            val violations: PasswordViolations,
        ) : AddUserResult

        data object AlreadyExists : AddUserResult
    }

    sealed interface ReplacePasswordResult {
        data object Success : ReplacePasswordResult

        data object UserNotFound : ReplacePasswordResult

        data class InvalidPassword(
            val violations: PasswordViolations,
        ) : ReplacePasswordResult
    }

    private companion object {
        /**
         * WebAuthn の user.id の上限は 64 バイト
         */
        const val USER_HANDLE_SIZE_BYTES = 32

        val USERNAME_PATTERN = Regex("^[A-Za-z0-9_.-]{1,64}$")
    }
}
