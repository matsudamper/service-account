package net.matsudamper.serviceaccount

import java.nio.file.Files
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration
import net.matsudamper.serviceaccount.db.Database
import net.matsudamper.serviceaccount.db.LoginFailureRepository
import net.matsudamper.serviceaccount.db.PasskeyChallengeRepository
import net.matsudamper.serviceaccount.db.PasskeyRepository
import net.matsudamper.serviceaccount.db.SessionRepository
import net.matsudamper.serviceaccount.db.UserId
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.logic.PasskeyService
import net.matsudamper.serviceaccount.logic.PasswordService
import net.matsudamper.serviceaccount.logic.SessionService
import net.matsudamper.serviceaccount.logic.UserAdminService
import net.matsudamper.serviceaccount.token.AccessTokenService

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
    val accessTokenService = AccessTokenService(SIGNING_JWK, issuer = ISSUER, ttl = 10.minutes, clock = clock)
    val sessionService = SessionService(SessionRepository(database), userRepository, accessTokenService, refreshTokenTtl = 30.days, clock = clock)
    val passwordService = PasswordService(userRepository, LoginFailureRepository(database), maxLoginFailures = maxLoginFailures, lockDuration = 15.minutes, clock = clock)
    val passkeyService = PasskeyService(passkeyRepository, PasskeyChallengeRepository(database), userRepository, clock)
    val userAdminService = UserAdminService(userRepository, clock)

    fun addUser(
        username: String = "alice",
        password: String = PASSWORD,
    ): UserId = (userAdminService.addUser(username, password) as UserAdminService.AddUserResult.Success).userId

    companion object {
        const val ISSUER = "https://auth.example.com"
        const val PASSWORD = "correct-horse-battery-staple"
        val SIGNING_JWK: String = AccessTokenService.generatePrivateJwkJson()
    }
}
