package net.matsudamper.serviceaccount.client

import java.io.Closeable
import java.util.concurrent.TimeUnit
import io.grpc.Channel
import io.grpc.ClientInterceptors
import io.grpc.ManagedChannel
import io.grpc.ManagedChannelBuilder
import io.grpc.Metadata
import io.grpc.stub.MetadataUtils
import net.matsudamper.serviceaccount.proto.v1.AccountServiceGrpcKt
import net.matsudamper.serviceaccount.proto.v1.AuthServiceGrpcKt

/**
 * service-account への接続。すべての呼び出しにクライアント ID とシークレットを付ける。
 *
 * ```kotlin
 * val client = ServiceAccountClient.create(host = "service-account", port = 50051, clientId = "kake-bo", clientSecret = secret)
 * val response = client.auth.loginWithPassword(loginWithPasswordRequest { ... })
 * ```
 */
class ServiceAccountClient(
    channel: Channel,
    clientId: String,
    clientSecret: String,
    private val ownedChannel: ManagedChannel? = null,
) : Closeable {
    private val authenticatedChannel: Channel = ClientInterceptors.intercept(channel, MetadataUtils.newAttachHeadersInterceptor(credentialHeaders(clientId, clientSecret)))

    val auth: AuthServiceGrpcKt.AuthServiceCoroutineStub = AuthServiceGrpcKt.AuthServiceCoroutineStub(authenticatedChannel)

    val account: AccountServiceGrpcKt.AccountServiceCoroutineStub = AccountServiceGrpcKt.AccountServiceCoroutineStub(authenticatedChannel)

    /**
     * [create] で作った接続だけを閉じる。外から渡した Channel は呼び出し側が閉じる
     */
    override fun close() {
        val channel = ownedChannel ?: return
        channel.shutdown()
        if (!channel.awaitTermination(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            channel.shutdownNow()
        }
    }

    companion object {
        private const val SHUTDOWN_TIMEOUT_SECONDS = 5L

        private val CLIENT_ID_KEY: Metadata.Key<String> = Metadata.Key.of("x-client-id", Metadata.ASCII_STRING_MARSHALLER)
        private val AUTHORIZATION_KEY: Metadata.Key<String> = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER)

        /**
         * @param plaintext service-account は TLS を終端しないので、内部ネットワークで直接繋ぐなら true。
         * TLS を終端するリバースプロキシ越しなら false
         */
        fun create(
            host: String,
            port: Int,
            clientId: String,
            clientSecret: String,
            plaintext: Boolean = true,
        ): ServiceAccountClient {
            val channel =
                ManagedChannelBuilder
                    .forAddress(host, port)
                    .apply { if (plaintext) usePlaintext() else useTransportSecurity() }
                    .build()
            return ServiceAccountClient(channel = channel, clientId = clientId, clientSecret = clientSecret, ownedChannel = channel)
        }

        private fun credentialHeaders(
            clientId: String,
            clientSecret: String,
        ): Metadata =
            Metadata().apply {
                put(CLIENT_ID_KEY, clientId)
                put(AUTHORIZATION_KEY, "Bearer $clientSecret")
            }
    }
}
