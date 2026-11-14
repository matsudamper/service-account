package net.matsudamper.serviceaccount.web

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
class PasswordLoginRequest(
    val username: String,
    val password: String,
    /**
     * アプリがログイントークンを受け取るときに、渡す先のサービスのクライアント ID を入れる
     */
    val clientId: String? = null,
)

@Serializable
class PasskeyLoginRequest(
    /**
     * AuthenticationResponseJSON
     */
    val credential: JsonObject,
    val clientId: String? = null,
)

@Serializable
class LoginResponse(
    /**
     * パスワードやパスキーを操作するときに Authorization: Bearer で渡す
     */
    val accountToken: String,
    val accountTokenExpiresAtEpochMillis: Long,
    /**
     * clientId を渡したときだけ入る。そのサービスのバックエンドに渡す
     */
    val loginToken: String? = null,
    val loginTokenExpiresAtEpochMillis: Long? = null,
)

@Serializable
class AuthorizeRequestBody(
    val responseType: String,
    val clientId: String,
    val redirectUri: String,
    val state: String? = null,
    val codeChallenge: String,
    val codeChallengeMethod: String,
)

@Serializable
class AuthorizeResponse(
    val redirectUrl: String,
)

@Serializable
class AccountResponse(
    val userId: Long,
    val username: String,
    val hasPassword: Boolean,
    val passkeys: List<PasskeyResponse>,
)

@Serializable
class PasskeyResponse(
    /**
     * credential ID の base64url（パディング無し）
     */
    val id: String,
    val name: String,
    val createdAtEpochMillis: Long,
    val lastUsedAtEpochMillis: Long? = null,
)

@Serializable
class ChangePasswordRequest(
    val newPassword: String,
)

@Serializable
class RegisterPasskeyRequest(
    val name: String,
    /**
     * RegistrationResponseJSON
     */
    val credential: JsonObject,
)

@Serializable
class ErrorResponse(
    val error: String,
    val message: String? = null,
    /**
     * error が invalid_password のとき
     */
    val invalidLength: Boolean? = null,
    val invalidCharacters: String? = null,
)
