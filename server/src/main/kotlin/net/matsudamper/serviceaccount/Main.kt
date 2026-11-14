package net.matsudamper.serviceaccount

import java.io.File
import java.time.Clock
import kotlin.system.exitProcess
import kotlin.time.Duration.Companion.hours
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import net.matsudamper.serviceaccount.cli.UserCli
import net.matsudamper.serviceaccount.client.ServiceConfig
import net.matsudamper.serviceaccount.db.AuthorizationCodeRepository
import net.matsudamper.serviceaccount.db.Database
import net.matsudamper.serviceaccount.db.LoginFailureRepository
import net.matsudamper.serviceaccount.db.PasskeyChallengeRepository
import net.matsudamper.serviceaccount.db.PasskeyRepository
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.grpc.AuthGrpcService
import net.matsudamper.serviceaccount.grpc.GrpcServer
import net.matsudamper.serviceaccount.logic.AuthorizationService
import net.matsudamper.serviceaccount.logic.PasskeyService
import net.matsudamper.serviceaccount.logic.PasswordService
import net.matsudamper.serviceaccount.logic.UserAdminService
import net.matsudamper.serviceaccount.passkey.PasskeyRelyingParty
import net.matsudamper.serviceaccount.token.TokenService
import net.matsudamper.serviceaccount.web.WebDependencies
import net.matsudamper.serviceaccount.web.webModule
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

        "generate-signing-key" -> println(TokenService.generatePrivateJwkJson())

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
    val config = ServiceConfig.parse(env.configJson)
    val publicUrl = env.publicUrl
    val relyingParty =
        PasskeyRelyingParty(
            id = checkNotNull(publicUrl.host) { "SERVICE_ACCOUNT_PUBLIC_URL にホスト名が無い" },
            origins = setOf(publicUrl.toString()) + config.androidApps.flatMap { it.passkeyOrigins },
        )
    val userRepository = UserRepository(database)
    val tokenService =
        TokenService(
            privateJwkJson = env.signingJwk,
            issuer = env.issuer,
            loginTokenTtl = env.loginTokenTtl,
            accountTokenTtl = env.accountTokenTtl,
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
            relyingParty = relyingParty,
            passkeyRepository = PasskeyRepository(database),
            challengeRepository = PasskeyChallengeRepository(database),
            userRepository = userRepository,
            clock = clock,
        )
    val authorizationService =
        AuthorizationService(
            clientRegistry = config.clientRegistry,
            codeRepository = AuthorizationCodeRepository(database),
            userRepository = userRepository,
            tokenService = tokenService,
            clock = clock,
        )

    val grpcServer =
        GrpcServer
            .create(
                port = env.grpcPort,
                clientRegistry = config.clientRegistry,
                services = listOf(AuthGrpcService(authorizationService = authorizationService, tokenService = tokenService)),
            ).start()
    logger.info("gRPC サーバーを {} 番で起動した", env.grpcPort)

    val webServer =
        embeddedServer(CIO, port = env.httpPort) {
            webModule(
                WebDependencies(
                    clientRegistry = config.clientRegistry,
                    androidApps = config.androidApps,
                    userRepository = userRepository,
                    passwordService = passwordService,
                    passkeyService = passkeyService,
                    authorizationService = authorizationService,
                    tokenService = tokenService,
                    trustCfConnectingIp = env.trustCfConnectingIp,
                ),
            )
        }.start(wait = false)
    logger.info("HTTP サーバーを {} 番で起動した。RP ID: {} origin: {}", env.httpPort, relyingParty.id, relyingParty.origins.joinToString())

    Runtime.getRuntime().addShutdownHook(
        Thread {
            webServer.stop()
            grpcServer.shutdown()
        },
    )

    runBlocking {
        while (true) {
            runCatching {
                passkeyService.deleteExpiredChallenges()
                passwordService.deleteExpiredLoginFailures()
                authorizationService.deleteExpired()
            }.onFailure { logger.warn("期限切れの記録を消せなかった", it) }
            delay(1.hours)
        }
    }
}
