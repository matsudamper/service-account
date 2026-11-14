package net.matsudamper.serviceaccount.grpc

import io.grpc.ForwardingServerCall
import io.grpc.Metadata
import io.grpc.ServerCall
import io.grpc.ServerCallHandler
import io.grpc.ServerInterceptor
import io.grpc.Status
import org.slf4j.LoggerFactory

/**
 * 実装から漏れた例外は UNKNOWN として返るだけでどこにも残らないので、ここで記録する
 */
class ErrorLoggingInterceptor : ServerInterceptor {
    override fun <ReqT, RespT> interceptCall(
        call: ServerCall<ReqT, RespT>,
        headers: Metadata,
        next: ServerCallHandler<ReqT, RespT>,
    ): ServerCall.Listener<ReqT> =
        next.startCall(
            object : ForwardingServerCall.SimpleForwardingServerCall<ReqT, RespT>(call) {
                override fun close(
                    status: Status,
                    trailers: Metadata,
                ) {
                    val cause = status.cause
                    if (cause != null) {
                        logger.error("{} が {} で失敗した", call.methodDescriptor.fullMethodName, status.code, cause)
                    }
                    super.close(status, trailers)
                }
            },
            headers,
        )

    private companion object {
        private val logger = LoggerFactory.getLogger(ErrorLoggingInterceptor::class.java)
    }
}
