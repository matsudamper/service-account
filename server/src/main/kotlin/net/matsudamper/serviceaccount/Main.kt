package net.matsudamper.serviceaccount

import java.io.File
import java.time.Clock
import kotlin.system.exitProcess
import kotlin.time.Duration.Companion.hours
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import net.matsudamper.serviceaccount.cli.UserCli
import net.matsudamper.serviceaccount.client.ClientRegistry
import net.matsudamper.serviceaccount.db.Database
import net.matsudamper.serviceaccount.db.LoginFailureRepository
import net.matsudamper.serviceaccount.db.PasskeyChallengeRepository
import net.matsudamper.serviceaccount.db.PasskeyRepository
import net.matsudamper.serviceaccount.db.SessionRepository
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.grpc.AccountGrpcService
import net.matsudamper.serviceaccount.grpc.AuthGrpcService
import net.matsudamper.serviceaccount.grpc.GrpcServer
import net.matsudamper.serviceaccount.logic.PasskeyService
import net.matsudamper.serviceaccount.logic.PasswordService
import net.matsudamper.serviceaccount.logic.SessionService
import net.matsudamper.serviceaccount.logic.UserAdminService
import net.matsudamper.serviceaccount.token.AccessTokenService
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger("net.matsudamper.serviceaccount.Main")

private const val USAGE = """使い方:
  service-account serve                    gRPC サーバーを起動する（引数無しも同じ）
  service-account add-user <username>      ユーザーを追加する。パスワードは標準入力から 1 行で渡す
  service-account set-password <username>  パスワードを置き換える。パスワードは標準入力から 1 行で渡す
  service-account generate-signing-key     JWT の署名鍵（秘密鍵を含む JWK）を出力する
  service-account generate-client-secret   クライアントシークレットと、設定ファイルに書くハッシュを出力する"""

fun main(args: Array<String>) {
    val env = ServerEnv()
    when (args.firstOrNull() ?: "serve") {
        "serve" -> serve(env)

        "add-user" -> exitProcess(UserCli(userAdminService(env)).addUser(args.getOrNull(1)))

        "set-password" -> exitProcess(UserCli(userAdminService(env)).setPassword(args.getOrNull(1)))

        "generate-signing-key" -> println(AccessTokenService.generatePrivateJwkJson())

        "generate-client-secret" -> UserCli.printClientSecret()

        else -> {
            System.err.println(USAGE)
            exitProcess(1)
        }
    }
}

private fun openDatabase(env: ServerEnv): Database {
    File(env.databasePath).absoluteFile.parentFile?.mkdirs()
    return Database(env.databasePath).also { it.migrate() }
}

private fun userAdminService(env: ServerEnv): UserAdminService = UserAdminService(UserRepository(openDatabase(env)), Clock.systemUTC())

private fun serve(env: ServerEnv) {
    val clock = Clock.systemUTC()
    val database = openDatabase(env)
    val clientRegistry = ClientRegistry.parse(env.clientsJson)
    val userRepository = UserRepository(database)
    val accessTokenService =
        AccessTokenService(
            privateJwkJson = env.signingJwk,
            issuer = env.issuer,
            ttl = env.accessTokenTtl,
            clock = clock,
        )
    val sessionService =
        SessionService(
            sessionRepository = SessionRepository(database),
            userRepository = userRepository,
            accessTokenService = accessTokenService,
            refreshTokenTtl = env.refreshTokenTtl,
            clock = clock,
        )
    val passwordService =
        PasswordService(
            userRepository = userRepository,
            loginFailureRepository = LoginFailureRepository(database),
            maxLoginFailures = env.maxLoginFailures,
            lockDuration = env.loginLockDuration,
            clock = clock,
        )
    val passkeyService =
        PasskeyService(
            passkeyRepository = PasskeyRepository(database),
            challengeRepository = PasskeyChallengeRepository(database),
            userRepository = userRepository,
            clock = clock,
        )

    val server =
        GrpcServer.create(
            port = env.grpcPort,
            clientRegistry = clientRegistry,
            services =
            listOf(
                AuthGrpcService(
                    passwordService = passwordService,
                    passkeyService = passkeyService,
                    sessionService = sessionService,
                    accessTokenService = accessTokenService,
                ),
                AccountGrpcService(
                    userRepository = userRepository,
                    passwordService = passwordService,
                    passkeyService = passkeyService,
                    sessionService = sessionService,
                ),
            ),
        ).start()
    logger.info("gRPC サーバーを {} 番で起動した", env.grpcPort)
    Runtime.getRuntime().addShutdownHook(Thread { server.shutdown() })

    runBlocking {
        while (true) {
            runCatching {
                sessionService.deleteExpired()
                passkeyService.deleteExpiredChallenges()
                passwordService.deleteExpiredLoginFailures()
            }.onFailure { logger.warn("期限切れの記録を消せなかった", it) }
            delay(1.hours)
        }
    }
}
