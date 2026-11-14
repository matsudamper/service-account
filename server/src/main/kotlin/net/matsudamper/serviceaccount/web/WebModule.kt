package net.matsudamper.serviceaccount.web

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.plugins.origin
import io.ktor.server.request.contentLength
import io.ktor.server.request.header
import io.ktor.server.request.receiveText
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import io.ktor.server.routing.routing
import net.matsudamper.serviceaccount.client.AndroidApp
import net.matsudamper.serviceaccount.client.ClientRegistry
import net.matsudamper.serviceaccount.db.PasskeyDeleteResult
import net.matsudamper.serviceaccount.db.UserId
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.logic.AuthorizationRequest
import net.matsudamper.serviceaccount.logic.AuthorizationService
import net.matsudamper.serviceaccount.logic.PasskeyService
import net.matsudamper.serviceaccount.logic.PasswordLoginResult
import net.matsudamper.serviceaccount.logic.PasswordService
import net.matsudamper.serviceaccount.token.TokenClaims
import net.matsudamper.serviceaccount.token.TokenService

class WebDependencies(
    val clientRegistry: ClientRegistry,
    val androidApps: List<AndroidApp>,
    val userRepository: UserRepository,
    val passwordService: PasswordService,
    val passkeyService: PasskeyService,
    val authorizationService: AuthorizationService,
    val tokenService: TokenService,
    /**
     * Cloudflare の後ろに置くときだけ true にする
     */
    val trustCfConnectingIp: Boolean,
)

/**
 * ログイン画面・アカウント設定画面と、それらとアプリが使う REST。
 *
 * ログイン状態は持たない。ログインに通ったらアカウントトークンを返し、画面の JavaScript やアプリがメモリに持って
 * Authorization ヘッダーで送る。Cookie を使わないので CSRF の対策は要らない
 */
fun Application.webModule(dependencies: WebDependencies) {
    val handler = WebHandler(dependencies)

    intercept(ApplicationCallPipeline.Plugins) {
        call.response.header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        call.response.header("X-Content-Type-Options", "nosniff")
        call.response.header("Referrer-Policy", "no-referrer")
        call.response.header(HttpHeaders.CacheControl, "no-store")
    }

    routing {
        get("/healthz") { call.respondText("ok") }

        get("/.well-known/assetlinks.json") { call.respondText(AssetLinks.json(dependencies.androidApps), ContentType.Application.Json) }

        get("/static/app.js") { call.respondText(StaticResources.text("web/static/app.js"), ContentType.Text.JavaScript) }
        get("/static/style.css") { call.respondText(StaticResources.text("web/static/style.css"), ContentType.Text.CSS) }

        get("/authorize") { handler.authorizePage(call) }
        get("/account") { call.respondText(Pages.account(), ContentType.Text.Html) }

        post("/api/login/password") { handler.passwordLogin(call) }
        post("/api/login/passkey/options") { call.respondJsonText(io { dependencies.passkeyService.loginOptions() }) }
        post("/api/login/passkey") { handler.passkeyLogin(call) }
        post("/api/authorize") { handler.authorize(call) }

        get("/api/account") { handler.account(call) }
        put("/api/account/password") { handler.changePassword(call) }
        delete("/api/account/password") { handler.deletePassword(call) }
        post("/api/account/passkeys/options") { handler.passkeyRegistrationOptions(call) }
        post("/api/account/passkeys") { handler.registerPasskey(call) }
        delete("/api/account/passkeys/{id}") { handler.deletePasskey(call) }
    }
}

private class WebHandler(
    private val dependencies: WebDependencies,
) {
    suspend fun authorizePage(call: ApplicationCall) {
        val parameters = call.request.queryParameters
        val request =
            AuthorizationRequest(
                responseType = parameters["response_type"].orEmpty(),
                clientId = parameters["client_id"].orEmpty(),
                redirectUri = parameters["redirect_uri"].orEmpty(),
                state = parameters["state"],
                codeChallenge = parameters["code_challenge"].orEmpty(),
                codeChallengeMethod = parameters["code_challenge_method"].orEmpty(),
            )
        val error = dependencies.authorizationService.validate(request)
        if (error != null) {
            call.respondText(Pages.error(error.message), ContentType.Text.Html, HttpStatusCode.BadRequest)
            return
        }
        call.respondText(Pages.authorize(request), ContentType.Text.Html)
    }

    suspend fun passwordLogin(call: ApplicationCall) {
        val body = call.receiveJson<PasswordLoginRequest>() ?: return
        if (!call.checkClientId(body.clientId)) return
        val clientIp = call.clientIp()
        when (val result = io { dependencies.passwordService.login(username = body.username, password = body.password, clientIp = clientIp) }) {
            is PasswordLoginResult.Success -> call.respondLogin(result.userId, body.clientId)
            PasswordLoginResult.NotAccepted -> call.respondError(HttpStatusCode.Unauthorized, "not_accepted")
            PasswordLoginResult.TooManyAttempts -> call.respondError(HttpStatusCode.TooManyRequests, "too_many_attempts")
        }
    }

    suspend fun passkeyLogin(call: ApplicationCall) {
        val body = call.receiveJson<PasskeyLoginRequest>() ?: return
        if (!call.checkClientId(body.clientId)) return
        val userId = io { dependencies.passkeyService.login(body.credential.toString()) }
        if (userId == null) {
            call.respondError(HttpStatusCode.Unauthorized, "not_accepted")
            return
        }
        call.respondLogin(userId, body.clientId)
    }

    suspend fun authorize(call: ApplicationCall) {
        val claims = call.authenticate() ?: return
        val body = call.receiveJson<AuthorizeRequestBody>() ?: return
        val request =
            AuthorizationRequest(
                responseType = body.responseType,
                clientId = body.clientId,
                redirectUri = body.redirectUri,
                state = body.state,
                codeChallenge = body.codeChallenge,
                codeChallengeMethod = body.codeChallengeMethod,
            )
        val error = dependencies.authorizationService.validate(request)
        if (error != null) {
            call.respondError(HttpStatusCode.BadRequest, "invalid_request", error.message)
            return
        }
        val redirectUrl = checkNotNull(io { dependencies.authorizationService.issueCode(request, claims.userId) })
        call.respondJson(AuthorizeResponse(redirectUrl))
    }

    suspend fun account(call: ApplicationCall) {
        val claims = call.authenticate() ?: return
        val user = io { dependencies.userRepository.findById(claims.userId) }
        if (user == null) {
            call.respondError(HttpStatusCode.Unauthorized, "unauthorized")
            return
        }
        val response =
            io {
                AccountResponse(
                    userId = user.id.value,
                    username = user.username,
                    hasPassword = dependencies.passwordService.hasPassword(user.id),
                    passkeys =
                    dependencies.passkeyService.passkeys(user.id).map { passkey ->
                        PasskeyResponse(
                            id = passkey.credentialId,
                            name = passkey.name,
                            createdAtEpochMillis = passkey.createdAt.toEpochMilli(),
                            lastUsedAtEpochMillis = passkey.lastUsedAt?.toEpochMilli(),
                        )
                    },
                )
            }
        call.respondJson(response)
    }

    suspend fun changePassword(call: ApplicationCall) {
        val claims = call.authenticate() ?: return
        val body = call.receiveJson<ChangePasswordRequest>() ?: return
        val violations = io { dependencies.passwordService.change(userId = claims.userId, newPassword = body.newPassword) }
        if (violations.isValid) {
            call.respond(HttpStatusCode.NoContent)
        } else {
            call.respondJson(
                ErrorResponse(
                    error = "invalid_password",
                    invalidLength = violations.invalidLength,
                    invalidCharacters = violations.invalidCharacters,
                ),
                HttpStatusCode.BadRequest,
            )
        }
    }

    suspend fun deletePassword(call: ApplicationCall) {
        val claims = call.authenticate() ?: return
        when (io { dependencies.passwordService.delete(claims.userId) }) {
            PasswordService.DeletePasswordResult.Success -> call.respond(HttpStatusCode.NoContent)
            PasswordService.DeletePasswordResult.NoPasskey -> call.respondError(HttpStatusCode.Conflict, "no_passkey")
        }
    }

    suspend fun passkeyRegistrationOptions(call: ApplicationCall) {
        val claims = call.authenticate() ?: return
        val user = io { dependencies.userRepository.findById(claims.userId) }
        if (user == null) {
            call.respondError(HttpStatusCode.Unauthorized, "unauthorized")
            return
        }
        call.respondJsonText(io { dependencies.passkeyService.registrationOptions(user) })
    }

    suspend fun registerPasskey(call: ApplicationCall) {
        val claims = call.authenticate() ?: return
        val body = call.receiveJson<RegisterPasskeyRequest>() ?: return
        val result = io { dependencies.passkeyService.register(userId = claims.userId, name = body.name, credentialJson = body.credential.toString()) }
        when (result) {
            PasskeyService.RegistrationResult.Success -> call.respond(HttpStatusCode.Created)
            PasskeyService.RegistrationResult.NotAccepted -> call.respondError(HttpStatusCode.BadRequest, "not_accepted")
            PasskeyService.RegistrationResult.InvalidName -> call.respondError(HttpStatusCode.BadRequest, "invalid_name")
            PasskeyService.RegistrationResult.AlreadyRegistered -> call.respondError(HttpStatusCode.Conflict, "already_registered")
        }
    }

    suspend fun deletePasskey(call: ApplicationCall) {
        val claims = call.authenticate() ?: return
        val credentialId = call.parameters["id"].orEmpty()
        when (io { dependencies.passkeyService.delete(userId = claims.userId, credentialId = credentialId) }) {
            PasskeyDeleteResult.Success -> call.respond(HttpStatusCode.NoContent)
            PasskeyDeleteResult.NotFound -> call.respondError(HttpStatusCode.NotFound, "not_found")
            PasskeyDeleteResult.LastLoginMethod -> call.respondError(HttpStatusCode.Conflict, "last_login_method")
        }
    }

    private suspend fun ApplicationCall.respondLogin(
        userId: UserId,
        clientId: String?,
    ) {
        val user = checkNotNull(io { dependencies.userRepository.findById(userId) }) { "ログインしたユーザーがいない" }
        val accountToken = dependencies.tokenService.issueAccountToken(userId = user.id, username = user.username)
        val loginToken = clientId?.let { dependencies.tokenService.issueLoginToken(userId = user.id, username = user.username, clientId = it) }
        respondJson(
            LoginResponse(
                accountToken = accountToken.token,
                accountTokenExpiresAtEpochMillis = accountToken.expiresAt.toEpochMilli(),
                loginToken = loginToken?.token,
                loginTokenExpiresAtEpochMillis = loginToken?.expiresAt?.toEpochMilli(),
            ),
        )
    }

    /**
     * 応答済みなら false
     */
    private suspend fun ApplicationCall.checkClientId(clientId: String?): Boolean {
        if (clientId == null || dependencies.clientRegistry.find(clientId) != null) return true
        respondError(HttpStatusCode.BadRequest, "unknown_client")
        return false
    }

    /**
     * 通らなければ 401 を返して null
     */
    private suspend fun ApplicationCall.authenticate(): TokenClaims? {
        val token = request.header(HttpHeaders.Authorization)?.removePrefix(BEARER_PREFIX)
        val claims = token?.let { dependencies.tokenService.verifyAccountToken(it) }
        if (claims == null) respondError(HttpStatusCode.Unauthorized, "unauthorized")
        return claims
    }

    /**
     * Cloudflare の後ろでは接続元が Cloudflare になり、全員がまとめて締め出されるので CF-Connecting-IP を使う
     */
    private fun ApplicationCall.clientIp(): String =
        request.header("CF-Connecting-IP")?.takeIf { dependencies.trustCfConnectingIp }
            ?: request.origin.remoteAddress

    private companion object {
        const val BEARER_PREFIX = "Bearer "
    }
}

private val json = Json { ignoreUnknownKeys = true }

/**
 * 本文が大きすぎるか読めなければ応答して null
 */
private suspend inline fun <reified T> ApplicationCall.receiveJson(): T? {
    val length = request.contentLength()
    if (length == null || length > MAX_REQUEST_BODY_BYTES) {
        respondError(HttpStatusCode.PayloadTooLarge, "payload_too_large")
        return null
    }
    return try {
        json.decodeFromString<T>(receiveText())
    } catch (_: SerializationException) {
        respondError(HttpStatusCode.BadRequest, "invalid_json")
        null
    } catch (_: IllegalArgumentException) {
        respondError(HttpStatusCode.BadRequest, "invalid_json")
        null
    }
}

private suspend inline fun <reified T> ApplicationCall.respondJson(
    body: T,
    status: HttpStatusCode = HttpStatusCode.OK,
) {
    respondText(json.encodeToString(body), ContentType.Application.Json, status)
}

private suspend fun ApplicationCall.respondJsonText(body: String) {
    respondText(body, ContentType.Application.Json)
}

private suspend fun ApplicationCall.respondError(
    status: HttpStatusCode,
    error: String,
    message: String? = null,
) {
    respondJson(ErrorResponse(error = error, message = message), status)
}

/**
 * SQLite と Argon2 はスレッドを止めるので、Ktor のスレッドでは行わない
 */
private suspend fun <T> io(block: () -> T): T = withContext(Dispatchers.IO) { block() }

/**
 * パスキーの応答は数 KB に収まる
 */
private const val MAX_REQUEST_BODY_BYTES = 64L * 1024

/**
 * 画面の JavaScript と CSS は自分のものだけを読む。inline の script を許さず、XSS でアカウントトークンを盗まれにくくする
 */
private const val CONTENT_SECURITY_POLICY =
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
        "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
