package net.matsudamper.serviceaccount.passkey

import com.webauthn4j.WebAuthnManager
import com.webauthn4j.converter.AttestedCredentialDataConverter
import com.webauthn4j.converter.exception.DataConversionException
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.data.AuthenticationData
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.RegistrationData
import com.webauthn4j.data.RegistrationParameters
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.Challenge
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.util.Base64UrlUtil
import com.webauthn4j.verifier.exception.VerificationException
import tools.jackson.core.JacksonException

/**
 * 受け取った応答を [parseRegistration] / [parseAuthentication] で読み、呼び出し側が challenge を
 * 発行済みのものと突き合わせて使い捨てにしてから、[verifyRegistration] / [verifyAuthentication] で検証する。
 *
 * attestation は求めない（"none"）。パスワードの代わりにするので、本人確認（UV）は必須にする
 */
class PasskeyVerifier(
    private val relyingParty: PasskeyRelyingParty,
) {
    /**
     * 登録で受け付ける署名方式の COSE の値。登録の要求に載せて、認証器にこの中から選ばせる
     */
    val supportedAlgorithms: List<Long> = SUPPORTED_ALGORITHMS.map { it.value }

    private val objectConverter = ObjectConverter()
    private val webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter)
    private val origins = relyingParty.origins.map(Origin::create).toSet()
    private val attestedCredentialDataConverter = AttestedCredentialDataConverter(objectConverter)

    /**
     * @param credentialJson RegistrationResponseJSON
     * @throws PasskeyVerificationException
     */
    fun parseRegistration(credentialJson: String): PasskeyRegistration = PasskeyRegistration(convert { webAuthnManager.parseRegistrationResponseJSON(credentialJson) })

    /**
     * @throws PasskeyVerificationException
     */
    fun verifyRegistration(registration: PasskeyRegistration): RegisteredPasskey {
        val parameters =
            RegistrationParameters(
                serverProperty(registration.clientChallenge),
                SUPPORTED_ALGORITHMS.map { PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, it) },
                true,
                true,
            )
        val verified = convert { webAuthnManager.verify(registration.data, parameters) }
        val authenticatorData = checkNotNull(verified.attestationObject).authenticatorData
        val credential = checkNotNull(authenticatorData.attestedCredentialData)

        val attestedCredentialData = attestedCredentialDataConverter.convert(credential)
        if (attestedCredentialData.size > MAX_ATTESTED_CREDENTIAL_DATA_BYTES) throw PasskeyVerificationException("公開鍵が大きすぎる")
        return RegisteredPasskey(
            credentialId = credential.credentialId,
            attestedCredentialData = attestedCredentialData,
            signCount = authenticatorData.signCount,
        )
    }

    /**
     * @param credentialJson AuthenticationResponseJSON
     * @throws PasskeyVerificationException
     */
    fun parseAuthentication(credentialJson: String): PasskeyAuthentication = PasskeyAuthentication(convert { webAuthnManager.parseAuthenticationResponseJSON(credentialJson) })

    /**
     * @param attestedCredentialData 登録時の [RegisteredPasskey.attestedCredentialData]
     * @param storedSignCount 前回までに受け取った署名回数。増えていなければ通さない（どちらも 0 なら比べない）
     * @return 今回の署名回数。次回の [storedSignCount] に渡す
     * @throws PasskeyVerificationException
     */
    fun verifyAuthentication(
        authentication: PasskeyAuthentication,
        attestedCredentialData: ByteArray,
        storedSignCount: Long,
    ): Long {
        val credentialRecord =
            CredentialRecordImpl(
                NoneAttestationStatement(),
                true,
                null,
                null,
                storedSignCount,
                convert { attestedCredentialDataConverter.convert(attestedCredentialData) },
                null,
                null,
                null,
                null,
            )
        val parameters =
            AuthenticationParameters(
                serverProperty(authentication.clientChallenge),
                credentialRecord,
                null,
                true,
                true,
            )
        val verified = convert { webAuthnManager.verify(authentication.data, parameters) }
        return checkNotNull(verified.authenticatorData).signCount
    }

    private fun serverProperty(challenge: Challenge): ServerProperty = ServerProperty(origins, relyingParty.id, challenge)

    /**
     * 受け取った値は例外の文言に入りうるので、ログに出す文言には型名だけを使う
     */
    private fun <T> convert(block: () -> T): T =
        try {
            block()
        } catch (e: DataConversionException) {
            throw PasskeyVerificationException("読めない: ${e::class.simpleName}", e)
        } catch (e: VerificationException) {
            throw PasskeyVerificationException("検証に通らない: ${e::class.simpleName}", e)
        } catch (e: JacksonException) {
            throw PasskeyVerificationException("読めない: ${e::class.simpleName}", e)
        } catch (e: IllegalArgumentException) {
            throw PasskeyVerificationException("読めない: ${e::class.simpleName}", e)
        } catch (e: NullPointerException) {
            // webauthn4j は response などが欠けた JSON を読むと検証の前に NullPointerException を投げる
            throw PasskeyVerificationException("読めない: ${e::class.simpleName}", e)
        }

    private companion object {
        val SUPPORTED_ALGORITHMS: List<COSEAlgorithmIdentifier> =
            listOf(COSEAlgorithmIdentifier.ES256, COSEAlgorithmIdentifier.EdDSA, COSEAlgorithmIdentifier.RS256)

        /**
         * webauthn4j は RSA の鍵長を制限しない。巨大な鍵を保存させ、ログインのたびに読ませないため。
         * credential ID の上限 1023 バイトと RSA 4096 bit の公開鍵が収まる大きさにしている
         */
        const val MAX_ATTESTED_CREDENTIAL_DATA_BYTES = 2048
    }
}

class PasskeyRegistration internal constructor(
    internal val data: RegistrationData,
) {
    internal val clientChallenge: Challenge = data.collectedClientData?.challenge ?: throw PasskeyVerificationException("challenge が無い")

    /**
     * base64url（パディング無し）
     */
    val challenge: String = Base64UrlUtil.encodeToString(clientChallenge.value)
}

class PasskeyAuthentication internal constructor(
    internal val data: AuthenticationData,
) {
    val credentialId: ByteArray = data.credentialId ?: throw PasskeyVerificationException("credential ID が無い")
    val userHandle: ByteArray? = data.userHandle

    internal val clientChallenge: Challenge = data.collectedClientData?.challenge ?: throw PasskeyVerificationException("challenge が無い")

    /**
     * base64url（パディング無し）
     */
    val challenge: String = Base64UrlUtil.encodeToString(clientChallenge.value)
}

/**
 * @param id RP ID。パスキーはこのドメインに紐づき、後から変えると登録済みのものが使えなくなる
 * @param origins clientDataJSON の origin として受け付ける値。ブラウザなら `https://example.com` の形
 */
class PasskeyRelyingParty(
    val id: String,
    val origins: Set<String>,
)

class RegisteredPasskey(
    val credentialId: ByteArray,
    /**
     * ログインの検証で [PasskeyVerifier.verifyAuthentication] に渡す
     */
    val attestedCredentialData: ByteArray,
    val signCount: Long,
)

class PasskeyVerificationException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)
