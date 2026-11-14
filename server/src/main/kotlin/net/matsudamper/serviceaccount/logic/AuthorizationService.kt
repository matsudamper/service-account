package net.matsudamper.serviceaccount.logic

import java.net.URI
import java.net.URLEncoder
import java.security.MessageDigest
import java.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration
import net.matsudamper.serviceaccount.client.ClientRegistry
import net.matsudamper.serviceaccount.db.AuthorizationCodeRepository
import net.matsudamper.serviceaccount.db.StoredAuthorizationCode
import net.matsudamper.serviceaccount.db.UserId
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.token.IssuedToken
import net.matsudamper.serviceaccount.token.TokenService

/**
 * OAuth 2.0 の認可コードフロー（PKCE は S256 だけ）。
 * ログイン画面で本人が通ったらコードを発行し、各サービスのバックエンドがクライアントシークレット付きでログイントークンに交換する
 */
class AuthorizationService(
    private val clientRegistry: ClientRegistry,
    private val codeRepository: AuthorizationCodeRepository,
    private val userRepository: UserRepository,
    private val tokenService: TokenService,
    private val clock: Clock,
) {
    /**
     * 画面を出す前と、コードを発行する前の両方で確かめる。
     * client_id か redirect_uri が通らないときは、攻撃者の URI へ戻さないよう redirect せずにエラーを出す
     */
    fun validate(request: AuthorizationRequest): AuthorizationRequestError? {
        val client = clientRegistry.find(request.clientId) ?: return AuthorizationRequestError.UnknownClient
        if (request.redirectUri !in client.redirectUris) return AuthorizationRequestError.UnregisteredRedirectUri
        if (request.responseType != RESPONSE_TYPE_CODE) return AuthorizationRequestError.UnsupportedResponseType
        if (request.codeChallengeMethod != CODE_CHALLENGE_METHOD_S256) return AuthorizationRequestError.InvalidCodeChallenge
        if (!CODE_CHALLENGE_PATTERN.matches(request.codeChallenge)) return AuthorizationRequestError.InvalidCodeChallenge
        return null
    }

    /**
     * @return 認可コードと state を付けて戻す先。[validate] が通らなければ null
     */
    fun issueCode(
        request: AuthorizationRequest,
        userId: UserId,
    ): String? {
        if (validate(request) != null) return null
        val code = SecureTokens.random(CODE_SIZE_BYTES)
        codeRepository.add(
            codeHash = SecureTokens.sha256(code),
            code =
            StoredAuthorizationCode(
                clientId = request.clientId,
                redirectUri = request.redirectUri,
                codeChallenge = request.codeChallenge,
                userId = userId,
                expiresAt = clock.instant().plus(CODE_TTL.toJavaDuration()),
            ),
        )
        return appendQuery(
            request.redirectUri,
            buildList {
                add("code" to code)
                request.state?.let { add("state" to it) }
            },
        )
    }

    /**
     * @return 期限切れ・使用済み・別クライアント・redirect_uri 違い・code_verifier 違いなら null
     */
    fun exchange(
        clientId: String,
        code: String,
        redirectUri: String,
        codeVerifier: String,
    ): IssuedToken? {
        val stored = codeRepository.consume(SecureTokens.sha256(code)) ?: return null
        if (stored.clientId != clientId) return null
        if (stored.redirectUri != redirectUri) return null
        if (!stored.expiresAt.isAfter(clock.instant())) return null
        if (!CODE_VERIFIER_PATTERN.matches(codeVerifier)) return null
        val expectedChallenge = SecureTokens.encode(MessageDigest.getInstance("SHA-256").digest(codeVerifier.encodeToByteArray()))
        if (!MessageDigest.isEqual(expectedChallenge.encodeToByteArray(), stored.codeChallenge.encodeToByteArray())) return null

        val user = userRepository.findById(stored.userId) ?: return null
        return tokenService.issueLoginToken(userId = user.id, username = user.username, clientId = clientId)
    }

    fun deleteExpired() {
        codeRepository.deleteExpired(clock.instant())
    }

    private fun appendQuery(
        uri: String,
        parameters: List<Pair<String, String>>,
    ): String {
        val query = parameters.joinToString("&") { (name, value) -> "$name=${URLEncoder.encode(value, Charsets.UTF_8)}" }
        val separator = if (URI(uri).rawQuery == null) "?" else "&"
        return uri + separator + query
    }

    private companion object {
        const val RESPONSE_TYPE_CODE = "code"
        const val CODE_CHALLENGE_METHOD_S256 = "S256"
        const val CODE_SIZE_BYTES = 32

        /**
         * 交換は戻ってすぐ行うので短くてよい
         */
        val CODE_TTL = 1.minutes

        /**
         * SHA-256 の base64url（パディング無し）は 43 文字
         */
        val CODE_CHALLENGE_PATTERN = Regex("^[A-Za-z0-9_-]{43}$")

        /**
         * RFC 7636 の code_verifier の文字と長さ
         */
        val CODE_VERIFIER_PATTERN = Regex("^[A-Za-z0-9._~-]{43,128}$")
    }
}

data class AuthorizationRequest(
    val responseType: String,
    val clientId: String,
    val redirectUri: String,
    val state: String?,
    val codeChallenge: String,
    val codeChallengeMethod: String,
)

enum class AuthorizationRequestError(
    val message: String,
) {
    UnknownClient("登録されていないクライアント"),
    UnregisteredRedirectUri("登録されていない redirect_uri"),
    UnsupportedResponseType("response_type は code だけに対応している"),
    InvalidCodeChallenge("code_challenge と code_challenge_method=S256 が必要"),
}
