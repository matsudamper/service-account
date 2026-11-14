package net.matsudamper.serviceaccount.grpc

import io.grpc.Context
import io.grpc.Contexts
import io.grpc.Metadata
import io.grpc.ServerCall
import io.grpc.ServerCallHandler
import io.grpc.ServerInterceptor
import io.grpc.Status
import net.matsudamper.serviceaccount.client.ClientRegistry
import net.matsudamper.serviceaccount.client.RegisteredClient

/**
 * 呼び出し元のサービスを x-client-id とシークレットで確かめ、[CURRENT_CLIENT] に入れる
 */
class ClientAuthInterceptor(
    private val clientRegistry: ClientRegistry,
) : ServerInterceptor {
    override fun <ReqT, RespT> interceptCall(
        call: ServerCall<ReqT, RespT>,
        headers: Metadata,
        next: ServerCallHandler<ReqT, RespT>,
    ): ServerCall.Listener<ReqT> {
        val clientId = headers.get(CLIENT_ID_KEY)
        val secret = headers.get(AUTHORIZATION_KEY)?.removePrefix(BEARER_PREFIX)?.takeIf { it.isNotEmpty() }
        val client = if (clientId != null && secret != null) clientRegistry.authenticate(clientId, secret) else null
        if (client == null) {
            call.close(Status.UNAUTHENTICATED.withDescription("クライアントの認証に失敗した"), Metadata())
            return object : ServerCall.Listener<ReqT>() {}
        }
        return Contexts.interceptCall(Context.current().withValue(CURRENT_CLIENT, client), call, headers, next)
    }

    companion object {
        val CURRENT_CLIENT: Context.Key<RegisteredClient> = Context.key("service-account-client")

        val CLIENT_ID_KEY: Metadata.Key<String> = Metadata.Key.of("x-client-id", Metadata.ASCII_STRING_MARSHALLER)
        val AUTHORIZATION_KEY: Metadata.Key<String> = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER)
        private const val BEARER_PREFIX = "Bearer "

        fun currentClient(): RegisteredClient = checkNotNull(CURRENT_CLIENT.get()) { "ClientAuthInterceptor を通っていない" }
    }
}
