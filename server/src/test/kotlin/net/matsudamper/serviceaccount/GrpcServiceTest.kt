package net.matsudamper.serviceaccount

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import io.grpc.ManagedChannel
import io.grpc.Metadata
import io.grpc.ServerInterceptors
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.inprocess.InProcessChannelBuilder
import io.grpc.inprocess.InProcessServerBuilder
import net.matsudamper.serviceaccount.client.ClientRegistry
import net.matsudamper.serviceaccount.client.RegisteredClient
import net.matsudamper.serviceaccount.grpc.AccountGrpcService
import net.matsudamper.serviceaccount.grpc.AuthGrpcService
import net.matsudamper.serviceaccount.grpc.ClientAuthInterceptor
import net.matsudamper.serviceaccount.passkey.PasskeyRelyingParty
import net.matsudamper.serviceaccount.proto.v1.AccountServiceGrpcKt
import net.matsudamper.serviceaccount.proto.v1.AuthServiceGrpcKt
import net.matsudamper.serviceaccount.proto.v1.LoginFailure
import net.matsudamper.serviceaccount.proto.v1.LoginResponse
import net.matsudamper.serviceaccount.proto.v1.getAccountRequest
import net.matsudamper.serviceaccount.proto.v1.loginWithPasswordRequest
import net.matsudamper.serviceaccount.proto.v1.verifyAccessTokenRequest

class GrpcServiceTest {
    private val fixture = TestFixture()
    private val serverName = InProcessServerBuilder.generateName()
    private val interceptor =
        ClientAuthInterceptor(
            ClientRegistry(
                listOf(
                    RegisteredClient(CLIENT_ID, ClientRegistry.hashSecret(SECRET), PasskeyRelyingParty("example.com", setOf("https://example.com"))),
                    RegisteredClient(OTHER_CLIENT_ID, ClientRegistry.hashSecret(SECRET), PasskeyRelyingParty("example.org", setOf("https://example.org"))),
                ),
            ),
        )
    private val server =
        InProcessServerBuilder
            .forName(serverName)
            .directExecutor()
            .addService(ServerInterceptors.intercept(AuthGrpcService(fixture.passwordService, fixture.passkeyService, fixture.sessionService, fixture.accessTokenService), interceptor))
            .addService(ServerInterceptors.intercept(AccountGrpcService(fixture.userRepository, fixture.passwordService, fixture.passkeyService, fixture.sessionService), interceptor))
            .build()
            .start()
    private val channel: ManagedChannel = InProcessChannelBuilder.forName(serverName).directExecutor().build()

    @AfterTest
    fun tearDown() {
        channel.shutdownNow()
        server.shutdownNow()
    }

    @Test
    fun ログインしたトークンでアカウントを読める() =
        runTest {
            fixture.addUser()
            val auth = AuthServiceGrpcKt.AuthServiceCoroutineStub(channel)
            val login = auth.loginWithPassword(loginRequest(), headers(CLIENT_ID, SECRET))
            assertEquals(LoginResponse.ResultCase.TOKENS, login.resultCase)

            val account = AccountServiceGrpcKt.AccountServiceCoroutineStub(channel)
            val response = account.getAccount(getAccountRequest { accessToken = login.tokens.accessToken }, headers(CLIENT_ID, SECRET))
            assertEquals("alice", response.username)
            assertTrue(response.hasPassword)
        }

    @Test
    fun 別のクライアントにはトークンが通らない() =
        runTest {
            fixture.addUser()
            val auth = AuthServiceGrpcKt.AuthServiceCoroutineStub(channel)
            val login = auth.loginWithPassword(loginRequest(), headers(CLIENT_ID, SECRET))

            val verified = auth.verifyAccessToken(verifyAccessTokenRequest { accessToken = login.tokens.accessToken }, headers(OTHER_CLIENT_ID, SECRET))
            assertEquals(false, verified.hasUser())
            val error =
                assertFailsWith<StatusException> {
                    AccountServiceGrpcKt
                        .AccountServiceCoroutineStub(channel)
                        .getAccount(getAccountRequest { accessToken = login.tokens.accessToken }, headers(OTHER_CLIENT_ID, SECRET))
                }
            assertEquals(Status.Code.UNAUTHENTICATED, error.status.code)
        }

    @Test
    fun クライアントのシークレットが違えば呼べない() =
        runTest {
            val error =
                assertFailsWith<StatusException> {
                    AuthServiceGrpcKt.AuthServiceCoroutineStub(channel).loginWithPassword(loginRequest(), headers(CLIENT_ID, "wrong"))
                }
            assertEquals(Status.Code.UNAUTHENTICATED, error.status.code)
        }

    @Test
    fun パスワードが違えば失敗を返す() =
        runTest {
            fixture.addUser()
            val response =
                AuthServiceGrpcKt.AuthServiceCoroutineStub(channel).loginWithPassword(
                    loginWithPasswordRequest {
                        username = "alice"
                        password = "wrong-password-wrong-password"
                        clientIp = "192.0.2.1"
                    },
                    headers(CLIENT_ID, SECRET),
                )
            assertEquals(LoginFailure.LOGIN_FAILURE_NOT_ACCEPTED, response.failure)
        }

    private fun loginRequest() =
        loginWithPasswordRequest {
            username = "alice"
            password = TestFixture.PASSWORD
            clientIp = "192.0.2.1"
            sessionName = "test"
        }

    private fun headers(
        clientId: String,
        secret: String,
    ) = Metadata().apply {
        put(ClientAuthInterceptor.CLIENT_ID_KEY, clientId)
        put(ClientAuthInterceptor.AUTHORIZATION_KEY, "Bearer $secret")
    }

    private companion object {
        const val CLIENT_ID = "kake-bo"
        const val OTHER_CLIENT_ID = "kmp-activitypub"
        const val SECRET = "client-secret"
    }
}
