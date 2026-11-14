package net.matsudamper.serviceaccount.grpc

import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.matsudamper.serviceaccount.logic.AuthorizationService
import net.matsudamper.serviceaccount.proto.v1.AuthServiceGrpcKt
import net.matsudamper.serviceaccount.proto.v1.AuthenticatedUser
import net.matsudamper.serviceaccount.proto.v1.ExchangeAuthorizationCodeRequest
import net.matsudamper.serviceaccount.proto.v1.ExchangeAuthorizationCodeResponse
import net.matsudamper.serviceaccount.proto.v1.GetJwksRequest
import net.matsudamper.serviceaccount.proto.v1.GetJwksResponse
import net.matsudamper.serviceaccount.proto.v1.VerifyLoginTokenRequest
import net.matsudamper.serviceaccount.proto.v1.VerifyLoginTokenResponse
import net.matsudamper.serviceaccount.proto.v1.authenticatedUser
import net.matsudamper.serviceaccount.proto.v1.exchangeAuthorizationCodeResponse
import net.matsudamper.serviceaccount.proto.v1.getJwksResponse
import net.matsudamper.serviceaccount.proto.v1.loginToken
import net.matsudamper.serviceaccount.proto.v1.verifyLoginTokenResponse
import net.matsudamper.serviceaccount.token.TokenClaims
import net.matsudamper.serviceaccount.token.TokenService

class AuthGrpcService(
    private val authorizationService: AuthorizationService,
    private val tokenService: TokenService,
    private val ioContext: CoroutineContext = Dispatchers.IO,
) : AuthServiceGrpcKt.AuthServiceCoroutineImplBase() {
    override suspend fun exchangeAuthorizationCode(request: ExchangeAuthorizationCodeRequest): ExchangeAuthorizationCodeResponse {
        val client = ClientAuthInterceptor.currentClient()
        return withContext(ioContext) {
            val issued =
                authorizationService.exchange(
                    clientId = client.id,
                    code = request.code,
                    redirectUri = request.redirectUri,
                    codeVerifier = request.codeVerifier,
                )
            val claims = issued?.let { tokenService.verifyLoginToken(token = it.token, clientId = client.id) }
            exchangeAuthorizationCodeResponse {
                if (issued != null && claims != null) {
                    token =
                        loginToken {
                            token = issued.token
                            expiresAtEpochMillis = issued.expiresAt.toEpochMilli()
                        }
                    user = claims.toProto()
                }
            }
        }
    }

    override suspend fun verifyLoginToken(request: VerifyLoginTokenRequest): VerifyLoginTokenResponse {
        val client = ClientAuthInterceptor.currentClient()
        val claims = tokenService.verifyLoginToken(token = request.token, clientId = client.id)
        return verifyLoginTokenResponse {
            if (claims != null) user = claims.toProto()
        }
    }

    override suspend fun getJwks(request: GetJwksRequest): GetJwksResponse = getJwksResponse { jwksJson = tokenService.publicJwkSetJson }

    private fun TokenClaims.toProto(): AuthenticatedUser =
        authenticatedUser {
            userId = this@toProto.userId.value
            username = this@toProto.username
        }
}
