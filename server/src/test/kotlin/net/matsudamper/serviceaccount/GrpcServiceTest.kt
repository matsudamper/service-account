package net.matsudamper.serviceaccount

import java.net.URI
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlinx.coroutines.test.runTest
import io.grpc.ManagedChannel
import io.grpc.Metadata
import io.grpc.ServerInterceptors
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.inprocess.InProcessChannelBuilder
import io.grpc.inprocess.InProcessServerBuilder
import net.matsudamper.serviceaccount.grpc.AuthGrpcService
import net.matsudamper.serviceaccount.grpc.ClientAuthInterceptor
import net.matsudamper.serviceaccount.logic.AuthorizationRequest
import net.matsudamper.serviceaccount.proto.v1.AuthServiceGrpcKt
import net.matsudamper.serviceaccount.proto.v1.exchangeAuthorizationCodeRequest
import net.matsudamper.serviceaccount.proto.v1.getJwksRequest
import net.matsudamper.serviceaccount.proto.v1.verifyLoginTokenRequest

class GrpcServiceTest {
    private val fixture = TestFixture()
    private val serverName = InProcessServerBuilder.generateName()
    private val server =
        InProcessServerBuilder
            .forName(serverName)
            .directExecutor()
            .addService(
                ServerInterceptors.intercept(
                    AuthGrpcService(fixture.authorizationService, fixture.tokenService),
                    ClientAuthInterceptor(fixture.clientRegistry),
                ),
            ).build()
            .start()
    private val channel: ManagedChannel = InProcessChannelBuilder.forName(serverName).directExecutor().build()
    private val stub = AuthServiceGrpcKt.AuthServiceCoroutineStub(channel)

    @AfterTest
    fun tearDown() {
        channel.shutdownNow()
        server.shutdownNow()
    }

    @Test
    fun 認可コードをログイントークンに交換できる() =
        runTest {
            val userId = fixture.addUser()
            val code = issueCode(userId)

            val response =
                stub.exchangeAuthorizationCode(
                    exchangeAuthorizationCodeRequest {
                        this.code = code
                        redirectUri = TestFixture.REDIRECT_URI
                        codeVerifier = AuthorizationServiceTest.VERIFIER
                    },
                    headers(TestFixture.CLIENT_ID),
                )
            assertEquals(userId.value, response.user.userId)
            assertEquals("alice", response.user.username)

            val verified = stub.verifyLoginToken(verifyLoginTokenRequest { token = response.token.token }, headers(TestFixture.CLIENT_ID))
            assertEquals(userId.value, verified.user.userId)
        }

    @Test
    fun 別のクライアントのコードやトークンは通らない() =
        runTest {
            val userId = fixture.addUser()
            val response =
                stub.exchangeAuthorizationCode(
                    exchangeAuthorizationCodeRequest {
                        code = issueCode(userId)
                        redirectUri = TestFixture.REDIRECT_URI
                        codeVerifier = AuthorizationServiceTest.VERIFIER
                    },
                    headers(TestFixture.OTHER_CLIENT_ID),
                )
            assertEquals(false, response.hasToken())

            val loginToken = fixture.tokenService.issueLoginToken(userId, "alice", TestFixture.CLIENT_ID)
            val verified = stub.verifyLoginToken(verifyLoginTokenRequest { token = loginToken.token }, headers(TestFixture.OTHER_CLIENT_ID))
            assertEquals(false, verified.hasUser())
        }

    @Test
    fun クライアントのシークレットが違えば呼べない() =
        runTest {
            val error = assertFailsWith<StatusException> { stub.getJwks(getJwksRequest { }, headers(TestFixture.CLIENT_ID, "wrong")) }
            assertEquals(Status.Code.UNAUTHENTICATED, error.status.code)
        }

    private fun issueCode(userId: net.matsudamper.serviceaccount.db.UserId): String {
        val redirectUrl =
            assertNotNull(
                fixture.authorizationService.issueCode(
                    AuthorizationRequest(
                        responseType = "code",
                        clientId = TestFixture.CLIENT_ID,
                        redirectUri = TestFixture.REDIRECT_URI,
                        state = null,
                        codeChallenge = AuthorizationServiceTest.CHALLENGE,
                        codeChallengeMethod = "S256",
                    ),
                    userId,
                ),
            )
        return URI(redirectUrl).query.removePrefix("code=")
    }

    private fun headers(
        clientId: String,
        secret: String = TestFixture.CLIENT_SECRET,
    ) = Metadata().apply {
        put(ClientAuthInterceptor.CLIENT_ID_KEY, clientId)
        put(ClientAuthInterceptor.AUTHORIZATION_KEY, "Bearer $secret")
    }
}
