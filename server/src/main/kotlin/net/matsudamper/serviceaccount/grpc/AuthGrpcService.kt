package net.matsudamper.serviceaccount.grpc

import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.matsudamper.serviceaccount.client.RegisteredClient
import net.matsudamper.serviceaccount.db.UserId
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.logic.PasskeyService
import net.matsudamper.serviceaccount.logic.PasswordLoginResult
import net.matsudamper.serviceaccount.logic.PasswordService
import net.matsudamper.serviceaccount.proto.v1.AuthServiceGrpcKt
import net.matsudamper.serviceaccount.proto.v1.CreatePasskeyLoginOptionsRequest
import net.matsudamper.serviceaccount.proto.v1.CreatePasskeyLoginOptionsResponse
import net.matsudamper.serviceaccount.proto.v1.GetJwksRequest
import net.matsudamper.serviceaccount.proto.v1.GetJwksResponse
import net.matsudamper.serviceaccount.proto.v1.LoginFailure
import net.matsudamper.serviceaccount.proto.v1.LoginResponse
import net.matsudamper.serviceaccount.proto.v1.LoginWithPasskeyRequest
import net.matsudamper.serviceaccount.proto.v1.LoginWithPasswordRequest
import net.matsudamper.serviceaccount.proto.v1.VerifyLoginTokenRequest
import net.matsudamper.serviceaccount.proto.v1.VerifyLoginTokenResponse
import net.matsudamper.serviceaccount.proto.v1.authenticatedUser
import net.matsudamper.serviceaccount.proto.v1.createPasskeyLoginOptionsResponse
import net.matsudamper.serviceaccount.proto.v1.getJwksResponse
import net.matsudamper.serviceaccount.proto.v1.loginResponse
import net.matsudamper.serviceaccount.proto.v1.loginToken
import net.matsudamper.serviceaccount.proto.v1.verifyLoginTokenResponse
import net.matsudamper.serviceaccount.token.LoginTokenService

class AuthGrpcService(
    private val userRepository: UserRepository,
    private val passwordService: PasswordService,
    private val passkeyService: PasskeyService,
    private val loginTokenService: LoginTokenService,
    private val ioContext: CoroutineContext = Dispatchers.IO,
) : AuthServiceGrpcKt.AuthServiceCoroutineImplBase() {
    override suspend fun loginWithPassword(request: LoginWithPasswordRequest): LoginResponse {
        val client = ClientAuthInterceptor.currentClient()
        return withContext(ioContext) {
            when (val result = passwordService.login(username = request.username, password = request.password, clientIp = request.clientIp)) {
                is PasswordLoginResult.Success -> successResponse(client, result.userId)
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
                successResponse(client, userId)
            }
        }
    }

    override suspend fun verifyLoginToken(request: VerifyLoginTokenRequest): VerifyLoginTokenResponse {
        val client = ClientAuthInterceptor.currentClient()
        val claims = loginTokenService.verify(token = request.token, clientId = client.id)
        return verifyLoginTokenResponse {
            if (claims != null) {
                user =
                    authenticatedUser {
                        userId = claims.userId.value
                        username = claims.username
                    }
            }
        }
    }

    override suspend fun getJwks(request: GetJwksRequest): GetJwksResponse = getJwksResponse { jwksJson = loginTokenService.publicJwkSetJson }

    private fun successResponse(
        client: RegisteredClient,
        userId: UserId,
    ): LoginResponse {
        val user = checkNotNull(userRepository.findById(userId)) { "ログインしたユーザーがいない" }
        val issued = loginTokenService.issue(userId = user.id, username = user.username, clientId = client.id)
        return loginResponse {
            token =
                loginToken {
                    token = issued.token
                    expiresAtEpochMillis = issued.expiresAt.toEpochMilli()
                }
        }
    }
}
