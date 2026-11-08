package net.matsudamper.serviceaccount.grpc

import io.grpc.BindableService
import io.grpc.Server
import io.grpc.ServerInterceptors
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder
import io.grpc.protobuf.services.HealthStatusManager
import net.matsudamper.serviceaccount.client.ClientRegistry

/**
 * TLS は前段（リバースプロキシや内部ネットワーク）に任せ、ここでは平文で待ち受ける
 */
object GrpcServer {
    fun create(
        port: Int,
        clientRegistry: ClientRegistry,
        services: List<BindableService>,
    ): Server {
        val clientAuthInterceptor = ClientAuthInterceptor(clientRegistry)
        val errorLoggingInterceptor = ErrorLoggingInterceptor()
        val health = HealthStatusManager()
        return NettyServerBuilder
            .forPort(port)
            .apply {
                // 後に渡したものが先に動く。クライアントの認証で弾いたものは記録しない
                services.forEach { addService(ServerInterceptors.intercept(it, errorLoggingInterceptor, clientAuthInterceptor)) }
            }
            // コンテナのヘルスチェックはクライアントの認証無しで叩けるようにする
            .addService(health.healthService)
            .build()
    }
}
