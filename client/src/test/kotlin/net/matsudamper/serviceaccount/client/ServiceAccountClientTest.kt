package net.matsudamper.serviceaccount.client

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest
import io.grpc.Metadata
import io.grpc.ServerCall
import io.grpc.ServerCallHandler
import io.grpc.ServerInterceptor
import io.grpc.ServerInterceptors
import io.grpc.inprocess.InProcessChannelBuilder
import io.grpc.inprocess.InProcessServerBuilder
import net.matsudamper.serviceaccount.proto.v1.AuthServiceGrpcKt
import net.matsudamper.serviceaccount.proto.v1.GetJwksRequest
import net.matsudamper.serviceaccount.proto.v1.GetJwksResponse
import net.matsudamper.serviceaccount.proto.v1.getJwksRequest
import net.matsudamper.serviceaccount.proto.v1.getJwksResponse

class ServiceAccountClientTest {
    private val serverName = InProcessServerBuilder.generateName()
    private val receivedHeaders = mutableListOf<Metadata>()
    private val server =
        InProcessServerBuilder
            .forName(serverName)
            .directExecutor()
            .addService(
                ServerInterceptors.intercept(
                    object : AuthServiceGrpcKt.AuthServiceCoroutineImplBase() {
                        override suspend fun getJwks(request: GetJwksRequest): GetJwksResponse = getJwksResponse { jwksJson = "{}" }
                    },
                    object : ServerInterceptor {
                        override fun <ReqT, RespT> interceptCall(
                            call: ServerCall<ReqT, RespT>,
                            headers: Metadata,
                            next: ServerCallHandler<ReqT, RespT>,
                        ): ServerCall.Listener<ReqT> {
                            receivedHeaders += headers
                            return next.startCall(call, headers)
                        }
                    },
                ),
            ).build()
            .start()
    private val channel = InProcessChannelBuilder.forName(serverName).directExecutor().build()

    @AfterTest
    fun tearDown() {
        channel.shutdownNow()
        server.shutdownNow()
    }

    @Test
    fun クライアントIDとシークレットを付けて呼ぶ() =
        runTest {
            val client = ServiceAccountClient(channel = channel, clientId = "kake-bo", clientSecret = "secret")

            assertEquals("{}", client.auth.getJwks(getJwksRequest { }).jwksJson)
            val headers = receivedHeaders.single()
            assertEquals("kake-bo", headers.get(Metadata.Key.of("x-client-id", Metadata.ASCII_STRING_MARSHALLER)))
            assertEquals("Bearer secret", headers.get(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER)))
        }
}
