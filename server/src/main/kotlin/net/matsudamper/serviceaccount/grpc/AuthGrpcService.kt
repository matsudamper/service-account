package net.matsudamper.serviceaccount.grpc

import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.matsudamper.serviceaccount.logic.PasskeyService
import net.matsudamper.serviceaccount.logic.PasswordLoginResult
import net.matsudamper.serviceaccount.logic.PasswordService
import net.matsudamper.serviceaccount.logic.SessionService
import net.matsudamper.serviceaccount.logic.TokenSet
import net.matsudamper.serviceaccount.proto.v1.AuthServiceGrpcKt
import net.matsudamper.serviceaccount.proto.v1.CreatePasskeyLoginOptionsRequest
import net.matsudamper.serviceaccount.proto.v1.CreatePasskeyLoginOptionsResponse
import net.matsudamper.serviceaccount.proto.v1.GetJwksRequest
import net.matsudamper.serviceaccount.proto.v1.GetJwksResponse
import net.matsudamper.serviceaccount.proto.v1.LoginFailure
import net.matsudamper.serviceaccount.proto.v1.LoginResponse
import net.matsudamper.serviceaccount.proto.v1.LoginWithPasskeyRequest
import net.matsudamper.serviceaccount.proto.v1.LoginWithPasswordRequest
import net.matsudamper.serviceaccount.proto.v1.LogoutRequest
import net.matsudamper.serviceaccount.proto.v1.LogoutResponse
import net.matsudamper.serviceaccount.proto.v1.RefreshTokensRequest
import net.matsudamper.serviceaccount.proto.v1.RefreshTokensResponse
import net.matsudamper.serviceaccount.proto.v1.VerifyAccessTokenRequest
import net.matsudamper.serviceaccount.proto.v1.VerifyAccessTokenResponse
import net.matsudamper.serviceaccount.proto.v1.authenticatedUser
import net.matsudamper.serviceaccount.proto.v1.createPasskeyLoginOptionsResponse
import net.matsudamper.serviceaccount.proto.v1.getJwksResponse
import net.matsudamper.serviceaccount.proto.v1.loginResponse
import net.matsudamper.serviceaccount.proto.v1.logoutResponse
import net.matsudamper.serviceaccount.proto.v1.refreshTokensResponse
import net.matsudamper.serviceaccount.proto.v1.tokenSet
import net.matsudamper.serviceaccount.proto.v1.verifyAccessTokenResponse
import net.matsudamper.serviceaccount.token.AccessTokenService

class AuthGrpcService(
    private val passwordService: PasswordService,
    private val passkeyService: PasskeyService,
    private val sessionService: SessionService,
    private val accessTokenService: AccessTokenService,
    private val ioContext: CoroutineContext = Dispatchers.IO,
) : AuthServiceGrpcKt.AuthServiceCoroutineImplBase() {
    override suspend fun loginWithPassword(request: LoginWithPasswordRequest): LoginResponse {
        val client = ClientAuthInterceptor.currentClient()
        return withContext(ioContext) {
            when (val result = passwordService.login(username = request.username, password = request.password, clientIp = request.clientIp)) {
                is PasswordLoginResult.Success -> {
                    val tokens = sessionService.create(userId = result.userId, clientId = client.id, sessionName = request.sessionName)
                    loginResponse { this.tokens = tokens.toProto() }
                }

                PasswordLoginResult.NotAccepted -> loginResponse { failure = LoginFailure.LOGIN_FAILURE_NOT_ACCEPTED }

                PasswordLoginResult.TooManyAttempts -> loginResponse { failure = LoginFailure.LOGIN_FAILURE_TOO_MANY_ATTEMPTS }
            }
        }
    }

    override suspend fun createPasskeyLoginOptions(request: CreatePasskeyLoginOptionsRequest): CreatePasskeyLoginOptionsResponse {
        val client = ClientAuthInterceptor.currentClient()
        return withContext(ioContext) {
            createPasskeyLoginOptionsResponse { optionsJson = passkeyService.loginOptions(client) }
        }
    }

    override suspend fun loginWithPasskey(request: LoginWithPasskeyRequest): LoginResponse {
        val client = ClientAuthInterceptor.currentClient()
        return withContext(ioContext) {
            val userId = passkeyService.login(client = client, credentialJson = request.credentialJson)
            if (userId == null) {
                loginResponse { failure = LoginFailure.LOGIN_FAILURE_NOT_ACCEPTED }
            } else {
                val tokens = sessionService.create(userId = userId, clientId = client.id, sessionName = request.sessionName)
                loginResponse { this.tokens = tokens.toProto() }
            }
        }
    }

    override suspend fun refreshTokens(request: RefreshTokensRequest): RefreshTokensResponse {
        val client = ClientAuthInterceptor.currentClient()
        return withContext(ioContext) {
            val tokens = sessionService.refresh(refreshToken = request.refreshToken, clientId = client.id)
            refreshTokensResponse {
                if (tokens != null) this.tokens = tokens.toProto()
            }
        }
    }

    override suspend fun logout(request: LogoutRequest): LogoutResponse {
        val client = ClientAuthInterceptor.currentClient()
        withContext(ioContext) {
            sessionService.logout(refreshToken = request.refreshToken, clientId = client.id)
        }
        return logoutResponse { }
    }

    override suspend fun verifyAccessToken(request: VerifyAccessTokenRequest): VerifyAccessTokenResponse {
        val client = ClientAuthInterceptor.currentClient()
        return withContext(ioContext) {
            val user = sessionService.authenticate(accessToken = request.accessToken, clientId = client.id)
            verifyAccessTokenResponse {
                if (user != null) {
                    this.user =
                        authenticatedUser {
                            userId = user.userId.value
                            username = user.username
                            sessionId = user.sessionId
                        }
                }
            }
        }
    }

    override suspend fun getJwks(request: GetJwksRequest): GetJwksResponse = getJwksResponse { jwksJson = accessTokenService.publicJwkSetJson }

    private fun TokenSet.toProto() =
        tokenSet {
            accessToken = this@toProto.accessToken
            accessTokenExpiresAtEpochMillis = accessTokenExpiresAt.toEpochMilli()
            refreshToken = this@toProto.refreshToken
            refreshTokenExpiresAtEpochMillis = refreshTokenExpiresAt.toEpochMilli()
            sessionId = this@toProto.sessionId
        }
}
