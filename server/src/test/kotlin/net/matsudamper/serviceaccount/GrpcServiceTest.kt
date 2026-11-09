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
import net.matsudamper.serviceaccount.proto.v1.verifyLoginTokenRequest

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
            .addService(ServerInterceptors.intercept(AuthGrpcService(fixture.userRepository, fixture.passwordService, fixture.passkeyService, fixture.loginTokenService), interceptor))
            .addService(ServerInterceptors.intercept(AccountGrpcService(fixture.userRepository, fixture.passwordService, fixture.passkeyService), interceptor))
            .build()
            .start()
    private val channel: ManagedChannel = InProcessChannelBuilder.forName(serverName).directExecutor().build()

    @AfterTest
    fun tearDown() {
        channel.shutdownNow()
        server.shutdownNow()
    }

    @Test
    fun ログイントークンは発行先のクライアントでだけ通る() =
        runTest {
            val userId = fixture.addUser()
            val auth = AuthServiceGrpcKt.AuthServiceCoroutineStub(channel)
            val login = auth.loginWithPassword(loginRequest(), headers(CLIENT_ID, SECRET))
            assertEquals(LoginResponse.ResultCase.TOKEN, login.resultCase)

            val verified = auth.verifyLoginToken(verifyLoginTokenRequest { token = login.token.token }, headers(CLIENT_ID, SECRET))
            assertEquals(userId.value, verified.user.userId)
            assertEquals("alice", verified.user.username)

            val otherClient = auth.verifyLoginToken(verifyLoginTokenRequest { token = login.token.token }, headers(OTHER_CLIENT_ID, SECRET))
            assertEquals(false, otherClient.hasUser())
        }

    @Test
    fun ユーザーIDでアカウントを読める() =
        runTest {
            val userId = fixture.addUser()
            val account = AccountServiceGrpcKt.AccountServiceCoroutineStub(channel)

            val response = account.getAccount(getAccountRequest { this.userId = userId.value }, headers(CLIENT_ID, SECRET))
            assertEquals("alice", response.username)
            assertTrue(response.hasPassword)

            val error =
                assertFailsWith<StatusException> {
                    account.getAccount(getAccountRequest { this.userId = userId.value + 1 }, headers(CLIENT_ID, SECRET))
                }
            assertEquals(Status.Code.NOT_FOUND, error.status.code)
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
