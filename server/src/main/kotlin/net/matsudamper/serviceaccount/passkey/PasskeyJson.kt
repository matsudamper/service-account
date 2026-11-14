package net.matsudamper.serviceaccount.passkey

import kotlin.time.Duration
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.AuthenticatorSelectionCriteria
import com.webauthn4j.data.PublicKeyCredentialCreationOptions
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialRequestOptions
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.ResidentKeyRequirement
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.util.Base64UrlUtil

/**
 * WebAuthn Level 3 の options の JSON 表現。Web の parseCreationOptionsFromJSON と
 * Android の Credential Manager がそのまま扱える形で、バイト列は base64url（パディング無し）
 */
object PasskeyJson {
    private val objectConverter = ObjectConverter()

    /**
     * PublicKeyCredentialCreationOptionsJSON
     */
    fun creationOptions(
        relyingParty: PasskeyRelyingParty,
        challenge: String,
        userHandle: String,
        username: String,
        algorithms: List<Long>,
        excludeCredentialIds: List<String>,
        timeout: Duration,
    ): String =
        objectConverter.jsonConverter.writeValueAsString(
            PublicKeyCredentialCreationOptions(
                PublicKeyCredentialRpEntity(relyingParty.id, relyingParty.id),
                PublicKeyCredentialUserEntity(Base64UrlUtil.decode(userHandle), username, username),
                DefaultChallenge(challenge),
                algorithms.map { PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.create(it)) },
                timeout.inWholeMilliseconds,
                excludeCredentialIds.map { PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, Base64UrlUtil.decode(it), null) },
                AuthenticatorSelectionCriteria(null, true, ResidentKeyRequirement.REQUIRED, UserVerificationRequirement.REQUIRED),
                AttestationConveyancePreference.NONE,
                null,
            ),
        )

    /**
     * PublicKeyCredentialRequestOptionsJSON。allowCredentials を空にして、端末にあるこの RP のパスキーから選ばせる
     */
    fun requestOptions(
        relyingParty: PasskeyRelyingParty,
        challenge: String,
        timeout: Duration,
    ): String =
        objectConverter.jsonConverter.writeValueAsString(
            PublicKeyCredentialRequestOptions(
                DefaultChallenge(challenge),
                timeout.inWholeMilliseconds,
                relyingParty.id,
                listOf(),
                UserVerificationRequirement.REQUIRED,
                null,
            ),
        )
}
