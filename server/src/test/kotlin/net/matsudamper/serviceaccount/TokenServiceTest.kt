package net.matsudamper.serviceaccount

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.minutes
import net.matsudamper.serviceaccount.token.TokenService

class TokenServiceTest {
    @Test
    fun ログイントークンは発行先のクライアントで期限内なら通る() {
        val fixture = TestFixture()
        val userId = fixture.addUser()
        val issued = fixture.tokenService.issueLoginToken(userId = userId, username = "alice", clientId = TestFixture.CLIENT_ID)

        val claims = assertNotNull(fixture.tokenService.verifyLoginToken(issued.token, TestFixture.CLIENT_ID))
        assertEquals(userId, claims.userId)
        assertEquals("alice", claims.username)
        assertNull(fixture.tokenService.verifyLoginToken(issued.token, TestFixture.OTHER_CLIENT_ID))

        fixture.clock.advance(6.minutes)
        assertNull(fixture.tokenService.verifyLoginToken(issued.token, TestFixture.CLIENT_ID))
    }

    @Test
    fun アカウントトークンは期限内なら通る() {
        val fixture = TestFixture()
        val userId = fixture.addUser()
        val issued = fixture.tokenService.issueAccountToken(userId = userId, username = "alice")

        assertEquals(userId, fixture.tokenService.verifyAccountToken(issued.token)?.userId)
        fixture.clock.advance(11.minutes)
        assertNull(fixture.tokenService.verifyAccountToken(issued.token))
    }

    @Test
    fun ログイントークンとアカウントトークンは取り違えて使えない() {
        val fixture = TestFixture()
        val userId = fixture.addUser()
        val loginToken = fixture.tokenService.issueLoginToken(userId = userId, username = "alice", clientId = TestFixture.ISSUER)
        val accountToken = fixture.tokenService.issueAccountToken(userId = userId, username = "alice")

        // クライアント ID が発行者と同じでも、用途が違えば通さない
        assertNull(fixture.tokenService.verifyAccountToken(loginToken.token))
        assertNull(fixture.tokenService.verifyLoginToken(accountToken.token, TestFixture.ISSUER))
    }

    @Test
    fun 別の鍵で署名したものは通らない() {
        val fixture = TestFixture()
        val otherKey = TokenService(TokenService.generatePrivateJwkJson(), TestFixture.ISSUER, 5.minutes, 10.minutes, fixture.clock)
        val userId = fixture.addUser()

        assertNull(fixture.tokenService.verifyLoginToken(otherKey.issueLoginToken(userId, "alice", TestFixture.CLIENT_ID).token, TestFixture.CLIENT_ID))
        assertNull(fixture.tokenService.verifyAccountToken(otherKey.issueAccountToken(userId, "alice").token))
    }
}
