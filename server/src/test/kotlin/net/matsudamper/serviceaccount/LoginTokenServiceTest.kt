package net.matsudamper.serviceaccount

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.minutes
import net.matsudamper.serviceaccount.token.LoginTokenService

class LoginTokenServiceTest {
    @Test
    fun 発行先のクライアントで期限内なら通る() {
        val fixture = TestFixture()
        val userId = fixture.addUser()
        val issued = fixture.loginTokenService.issue(userId = userId, username = "alice", clientId = CLIENT_ID)

        val claims = assertNotNull(fixture.loginTokenService.verify(issued.token, CLIENT_ID))
        assertEquals(userId, claims.userId)
        assertEquals("alice", claims.username)
        assertNull(fixture.loginTokenService.verify(issued.token, "other"))
    }

    @Test
    fun 期限を過ぎると通らない() {
        val fixture = TestFixture()
        val issued = fixture.loginTokenService.issue(userId = fixture.addUser(), username = "alice", clientId = CLIENT_ID)

        fixture.clock.advance(6.minutes)
        assertNull(fixture.loginTokenService.verify(issued.token, CLIENT_ID))
    }

    @Test
    fun 別の鍵で署名したものは通らない() {
        val fixture = TestFixture()
        val otherKey = LoginTokenService(LoginTokenService.generatePrivateJwkJson(), TestFixture.ISSUER, 5.minutes, fixture.clock)
        val issued = otherKey.issue(userId = fixture.addUser(), username = "alice", clientId = CLIENT_ID)

        assertNull(fixture.loginTokenService.verify(issued.token, CLIENT_ID))
    }

    private companion object {
        const val CLIENT_ID = "kake-bo"
    }
}
