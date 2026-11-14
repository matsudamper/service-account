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
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import net.matsudamper.serviceaccount.db.UserId

/**
 * ES256 で署名した 2 種類の JWT を扱う。取り違えないよう `token_use` で見分ける。
 *
 * - ログイントークン: ログインに通ったことを、aud のクライアント（各サービス）に伝える。各サービスは検証したらすぐ自分のセッションを作る
 * - アカウントトークン: ログインした本人が、このサービスでパスワードやパスキーを操作するのに使う。aud はこのサービス自身
 *
 * @param privateJwkJson 秘密鍵を含む P-256 の EC JWK。kid 必須
 */
class TokenService(
    privateJwkJson: String,
    private val issuer: String,
    private val loginTokenTtl: Duration,
    private val accountTokenTtl: Duration,
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

    fun issueLoginToken(
        userId: UserId,
        username: String,
        clientId: String,
    ): IssuedToken = issue(TokenUse.Login, userId, username, audience = clientId, ttl = loginTokenTtl)

    /**
     * @return 署名・発行者・期限・aud が通らなければ null
     */
    fun verifyLoginToken(
        token: String,
        clientId: String,
    ): TokenClaims? = verify(token, TokenUse.Login, audience = clientId)

    fun issueAccountToken(
        userId: UserId,
        username: String,
    ): IssuedToken = issue(TokenUse.Account, userId, username, audience = issuer, ttl = accountTokenTtl)

    fun verifyAccountToken(token: String): TokenClaims? = verify(token, TokenUse.Account, audience = issuer)

    private fun issue(
        use: TokenUse,
        userId: UserId,
        username: String,
        audience: String,
        ttl: Duration,
    ): IssuedToken {
        val now = clock.instant()
        val expiresAt = now.plus(ttl.toJavaDuration())
        val claims =
            JWTClaimsSet
                .Builder()
                .issuer(issuer)
                .subject(userId.value.toString())
                .audience(audience)
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString())
                .claim(CLAIM_USERNAME, username)
                .claim(CLAIM_TOKEN_USE, use.claimValue)
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
        return IssuedToken(token = jwt.serialize(), expiresAt = expiresAt)
    }

    private fun verify(
        token: String,
        use: TokenUse,
        audience: String,
    ): TokenClaims? {
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
        if (claims.audience != listOf(audience)) return null
        if (claims.getClaim(CLAIM_TOKEN_USE) != use.claimValue) return null
        val expiresAt = claims.expirationTime ?: return null
        if (!now.before(expiresAt)) return null
        if (claims.notBeforeTime?.after(now) == true) return null

        return TokenClaims(
            userId = UserId(claims.subject?.toLongOrNull() ?: return null),
            username = claims.getClaim(CLAIM_USERNAME) as? String ?: return null,
        )
    }

    private enum class TokenUse(
        val claimValue: String,
    ) {
        Login("login"),
        Account("account"),
    }

    companion object {
        private const val CLAIM_USERNAME = "preferred_username"
        private const val CLAIM_TOKEN_USE = "token_use"

        fun generatePrivateJwkJson(): String =
            ECKeyGenerator(Curve.P_256)
                .keyIDFromThumbprint(true)
                .generate()
                .toJSONString()
    }
}

class IssuedToken(
    val token: String,
    val expiresAt: Instant,
)

data class TokenClaims(
    val userId: UserId,
    val username: String,
)
