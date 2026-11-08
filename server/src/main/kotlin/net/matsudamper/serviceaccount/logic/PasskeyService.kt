package net.matsudamper.serviceaccount.logic

import java.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration
import net.matsudamper.serviceaccount.client.RegisteredClient
import net.matsudamper.serviceaccount.db.PasskeyChallengePurpose
import net.matsudamper.serviceaccount.db.PasskeyChallengeRepository
import net.matsudamper.serviceaccount.db.PasskeyDeleteResult
import net.matsudamper.serviceaccount.db.PasskeyRepository
import net.matsudamper.serviceaccount.db.PasskeySummary
import net.matsudamper.serviceaccount.db.User
import net.matsudamper.serviceaccount.db.UserId
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.passkey.PasskeyJson
import net.matsudamper.serviceaccount.passkey.PasskeyVerificationException
import net.matsudamper.serviceaccount.passkey.PasskeyVerifier
import org.slf4j.LoggerFactory

/**
 * 認証器との受け渡しは [PasskeyJson] の JSON で行う。
 * パスキーは RP ID に紐づくので、呼び出し元クライアントの RP ID で登録したものだけをログインに使う
 */
class PasskeyService(
    private val passkeyRepository: PasskeyRepository,
    private val challengeRepository: PasskeyChallengeRepository,
    private val userRepository: UserRepository,
    private val clock: Clock,
) {
    private val verifiers = mutableMapOf<String, PasskeyVerifier>()

    /**
     * @return PublicKeyCredentialRequestOptionsJSON
     */
    fun loginOptions(client: RegisteredClient): String =
        PasskeyJson.requestOptions(
            relyingParty = client.relyingParty,
            challenge = issueChallenge(client, PasskeyChallengePurpose.Authentication, userId = null),
            timeout = CHALLENGE_TTL,
        )

    /**
     * @param credentialJson AuthenticationResponseJSON
     * @return 通ればログインするユーザー
     */
    fun login(
        client: RegisteredClient,
        credentialJson: String,
    ): UserId? =
        verifyOrNull {
            val verifier = verifierOf(client)
            val authentication = verifier.parseAuthentication(credentialJson)
            if (!challengeRepository.consume(authentication.challenge, PasskeyChallengePurpose.Authentication, client.id, userId = null, now = clock.instant())) {
                throw PasskeyVerificationException("発行していないか期限切れの challenge")
            }

            val credentialId = SecureTokens.encode(authentication.credentialId)
            val passkey =
                passkeyRepository.find(credentialId = credentialId, rpId = client.relyingParty.id)
                    ?: throw PasskeyVerificationException("登録されていない credential ID")
            val owner = userRepository.findById(passkey.userId) ?: throw PasskeyVerificationException("持ち主がいない")
            // 別のユーザーのパスキーで、このユーザーの user handle を名乗っていないかを見る
            val userHandle = authentication.userHandle
            if (userHandle != null && SecureTokens.encode(userHandle) != owner.passkeyUserHandle) throw PasskeyVerificationException("user handle が持ち主と合わない")

            val signCount =
                verifier.verifyAuthentication(
                    authentication = authentication,
                    attestedCredentialData = passkey.attestedCredentialData,
                    storedSignCount = passkey.signCount,
                )
            val updated =
                passkeyRepository.updateSignCount(
                    credentialId = credentialId,
                    expectedSignCount = passkey.signCount,
                    signCount = signCount,
                    usedAt = clock.instant(),
                )
            if (!updated) throw PasskeyVerificationException("同じパスキーのログインが同時に通った")
            owner.id
        }

    /**
     * @return PublicKeyCredentialCreationOptionsJSON
     */
    fun registrationOptions(
        client: RegisteredClient,
        user: User,
    ): String =
        PasskeyJson.creationOptions(
            relyingParty = client.relyingParty,
            challenge = issueChallenge(client, PasskeyChallengePurpose.Registration, userId = user.id),
            userHandle = user.passkeyUserHandle,
            username = user.username,
            algorithms = verifierOf(client).supportedAlgorithms,
            excludeCredentialIds = passkeyRepository.credentialIds(userId = user.id, rpId = client.relyingParty.id),
            timeout = CHALLENGE_TTL,
        )

    /**
     * @param credentialJson RegistrationResponseJSON
     */
    fun register(
        client: RegisteredClient,
        userId: UserId,
        name: String,
        credentialJson: String,
    ): RegistrationResult {
        val trimmedName = name.trim()
        if (trimmedName.isEmpty() || trimmedName.codePointCount(0, trimmedName.length) > MAX_NAME_LENGTH) return RegistrationResult.InvalidName

        val registered =
            verifyOrNull {
                val verifier = verifierOf(client)
                val registration = verifier.parseRegistration(credentialJson)
                // 別のユーザー・クライアント向けに発行した challenge では足させない
                if (!challengeRepository.consume(registration.challenge, PasskeyChallengePurpose.Registration, client.id, userId = userId, now = clock.instant())) {
                    throw PasskeyVerificationException("発行していないか期限切れの challenge")
                }
                verifier.verifyRegistration(registration)
            } ?: return RegistrationResult.NotAccepted

        val added =
            passkeyRepository.add(
                userId = userId,
                rpId = client.relyingParty.id,
                credentialId = SecureTokens.encode(registered.credentialId),
                attestedCredentialData = registered.attestedCredentialData,
                signCount = registered.signCount,
                name = trimmedName,
                createdAt = clock.instant(),
            )
        return if (added) RegistrationResult.Success else RegistrationResult.AlreadyRegistered
    }

    fun passkeys(userId: UserId): List<PasskeySummary> = passkeyRepository.passkeys(userId)

    fun delete(
        userId: UserId,
        credentialId: String,
    ): PasskeyDeleteResult = passkeyRepository.delete(userId = userId, credentialId = credentialId)

    fun deleteExpiredChallenges() {
        challengeRepository.deleteExpired(clock.instant())
    }

    private fun verifierOf(client: RegisteredClient): PasskeyVerifier =
        synchronized(verifiers) {
            verifiers.getOrPut(client.id) { PasskeyVerifier(client.relyingParty) }
        }

    private fun issueChallenge(
        client: RegisteredClient,
        purpose: PasskeyChallengePurpose,
        userId: UserId?,
    ): String {
        val challenge = SecureTokens.random(CHALLENGE_SIZE_BYTES)
        challengeRepository.add(
            challenge = challenge,
            purpose = purpose,
            clientId = client.id,
            userId = userId,
            expiresAt = clock.instant().plus(CHALLENGE_TTL.toJavaDuration()),
        )
        return challenge
    }

    private fun <T> verifyOrNull(block: () -> T): T? =
        try {
            block()
        } catch (e: PasskeyVerificationException) {
            // origin や RP ID の設定違いはここでしか分からない
            logger.info("パスキーの検証に通らなかった: {}", e.message)
            null
        }

    enum class RegistrationResult {
        Success,
        NotAccepted,
        AlreadyRegistered,
        InvalidName,
    }

    private companion object {
        private val logger = LoggerFactory.getLogger(PasskeyService::class.java)

        /**
         * WebAuthn は 16 バイト以上を求める
         */
        const val CHALLENGE_SIZE_BYTES = 32

        /**
         * 本人確認を求めるときに WebAuthn が勧めるタイムアウトの上限に合わせる
         */
        val CHALLENGE_TTL = 5.minutes

        const val MAX_NAME_LENGTH = 64
    }
}
