package net.matsudamper.serviceaccount.token

import java.text.ParseException
import java.time.Clock
import java.time.Instant
import java.util.Date
import java.util.UUID
import kotlin.time.Duration
import kotlin.time.toJavaDuration
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import net.matsudamper.serviceaccount.db.UserId

/**
 * ES256 で署名した JWT のアクセストークン。
 * 短命にして、セッションの削除は [AccessTokenClaims.sessionId] をサービス側で見て反映する
 *
 * @param privateJwkJson 秘密鍵を含む P-256 の EC JWK。kid 必須
 */
class AccessTokenService(
    privateJwkJson: String,
    private val issuer: String,
    private val ttl: Duration,
    private val clock: Clock,
) {
    private val key: ECKey = ECKey.parse(privateJwkJson)

    init {
        require(key.isPrivate) { "署名鍵の JWK には秘密鍵を含めること" }
        require(key.curve == Curve.P_256) { "署名鍵は P-256 にすること" }
        requireNotNull(key.keyID) { "署名鍵の JWK には kid を含めること" }
    }

    private val signer = ECDSASigner(key)
    private val verifier = ECDSAVerifier(key.toPublicJWK())

    val publicJwkSetJson: String = JWKSet(key.toPublicJWK()).toString()

    fun issue(
        userId: UserId,
        username: String,
        sessionId: String,
        clientId: String,
    ): IssuedAccessToken {
        val now = clock.instant()
        val expiresAt = now.plus(ttl.toJavaDuration())
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer(issuer)
                .subject(userId.value.toString())
                .audience(clientId)
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString())
                .claim(CLAIM_USERNAME, username)
                .claim(CLAIM_SESSION_ID, sessionId)
                .build()
        val jwt =
            SignedJWT(
                JWSHeader
                    .Builder(JWSAlgorithm.ES256)
                    .keyID(key.keyID)
                    .type(JOSEObjectType.JWT)
                    .build(),
                claims,
            )
        jwt.sign(signer)
        return IssuedAccessToken(token = jwt.serialize(), expiresAt = expiresAt)
    }

    /**
     * @return 署名・発行者・期限・aud が通らなければ null
     */
    fun verify(
        token: String,
        clientId: String,
    ): AccessTokenClaims? {
        val jwt =
            try {
                SignedJWT.parse(token)
            } catch (_: ParseException) {
                return null
            }
        if (jwt.header.algorithm != JWSAlgorithm.ES256) return null
        val verified =
            try {
                jwt.verify(verifier)
            } catch (_: JOSEException) {
                false
            }
        if (!verified) return null

        val claims =
            try {
                jwt.jwtClaimsSet
            } catch (_: ParseException) {
                return null
            }
        val now = Date.from(clock.instant())
        if (claims.issuer != issuer) return null
        if (claims.audience != listOf(clientId)) return null
        val expiresAt = claims.expirationTime ?: return null
        if (!now.before(expiresAt)) return null
        if (claims.notBeforeTime?.after(now) == true) return null

        return AccessTokenClaims(
            userId = UserId(claims.subject?.toLongOrNull() ?: return null),
            username = claims.getStringClaim(CLAIM_USERNAME) ?: return null,
            sessionId = claims.getStringClaim(CLAIM_SESSION_ID) ?: return null,
        )
    }

    companion object {
        private const val CLAIM_USERNAME = "preferred_username"
        private const val CLAIM_SESSION_ID = "sid"

        fun generatePrivateJwkJson(): String =
            com.nimbusds.jose.jwk.gen
                .ECKeyGenerator(Curve.P_256)
                .keyIDFromThumbprint(true)
                .generate()
                .toJSONString()
    }
}

class IssuedAccessToken(
    val token: String,
    val expiresAt: Instant,
)

data class AccessTokenClaims(
    val userId: UserId,
    val username: String,
    val sessionId: String,
)
