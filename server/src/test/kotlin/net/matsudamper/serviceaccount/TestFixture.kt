package net.matsudamper.serviceaccount

import java.nio.file.Files
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration
import net.matsudamper.serviceaccount.client.ClientRegistry
import net.matsudamper.serviceaccount.client.RegisteredClient
import net.matsudamper.serviceaccount.db.AuthorizationCodeRepository
import net.matsudamper.serviceaccount.db.Database
import net.matsudamper.serviceaccount.db.LoginFailureRepository
import net.matsudamper.serviceaccount.db.PasskeyChallengeRepository
import net.matsudamper.serviceaccount.db.PasskeyRepository
import net.matsudamper.serviceaccount.db.UserId
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.logic.AuthorizationService
import net.matsudamper.serviceaccount.logic.PasskeyService
import net.matsudamper.serviceaccount.logic.PasswordService
import net.matsudamper.serviceaccount.logic.UserAdminService
import net.matsudamper.serviceaccount.passkey.PasskeyRelyingParty
import net.matsudamper.serviceaccount.token.TokenService

class MutableClock(
    var now: Instant = Instant.parse("2026-01-01T00:00:00Z"),
) : Clock() {
    override fun getZone() = ZoneOffset.UTC

    override fun withZone(zone: java.time.ZoneId?): Clock = this

    override fun instant(): Instant = now

    fun advance(duration: Duration) {
        now = now.plus(duration.toJavaDuration())
    }
}

class TestFixture(
    maxLoginFailures: Int = 3,
) {
    val clock = MutableClock()
    val database: Database =
        Database(Files.createTempFile("service-account-test", ".db").toString()).also { it.migrate() }
    val userRepository = UserRepository(database)
    val passkeyRepository = PasskeyRepository(database)
    val tokenService = TokenService(SIGNING_JWK, issuer = ISSUER, loginTokenTtl = 5.minutes, accountTokenTtl = 10.minutes, clock = clock)
    val passwordService = PasswordService(userRepository, LoginFailureRepository(database), maxLoginFailures = maxLoginFailures, lockDuration = 15.minutes, clock = clock)
    val passkeyService = PasskeyService(RELYING_PARTY, passkeyRepository, PasskeyChallengeRepository(database), userRepository, clock)
    val clientRegistry =
        ClientRegistry(
            listOf(
                RegisteredClient(CLIENT_ID, ClientRegistry.hashSecret(CLIENT_SECRET), setOf(REDIRECT_URI)),
                RegisteredClient(OTHER_CLIENT_ID, ClientRegistry.hashSecret(CLIENT_SECRET), setOf("https://social.example.org/callback")),
            ),
        )
    val authorizationService = AuthorizationService(clientRegistry, AuthorizationCodeRepository(database), userRepository, tokenService, clock)
    val userAdminService = UserAdminService(userRepository, clock)

    fun addUser(
        username: String = "alice",
        password: String = PASSWORD,
    ): UserId = (userAdminService.addUser(username, password) as UserAdminService.AddUserResult.Success).userId

    companion object {
        const val ISSUER = "https://auth.example.com"
        const val PASSWORD = "correct-horse-battery-staple"
        const val CLIENT_ID = "kake-bo"
        const val OTHER_CLIENT_ID = "kmp-activitypub"
        const val CLIENT_SECRET = "client-secret"
        const val REDIRECT_URI = "https://money.example.com/login/callback"
        val RELYING_PARTY = PasskeyRelyingParty("auth.example.com", setOf("https://auth.example.com"))
        val SIGNING_JWK: String = TokenService.generatePrivateJwkJson()
    }
}
