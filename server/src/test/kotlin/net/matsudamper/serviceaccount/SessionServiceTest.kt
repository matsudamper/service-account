package net.matsudamper.serviceaccount

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import net.matsudamper.serviceaccount.logic.SessionService

class SessionServiceTest {
    @Test
    fun 発行したアクセストークンは発行先のクライアントでだけ通る() {
        val fixture = TestFixture()
        val userId = fixture.addUser()
        val tokens = fixture.sessionService.create(userId, CLIENT_ID, "browser")

        val user = assertNotNull(fixture.sessionService.authenticate(tokens.accessToken, CLIENT_ID))
        assertEquals(userId, user.userId)
        assertEquals("alice", user.username)
        assertNull(fixture.sessionService.authenticate(tokens.accessToken, "other"))
    }

    @Test
    fun アクセストークンは期限を過ぎると通らない() {
        val fixture = TestFixture()
        val tokens = fixture.sessionService.create(fixture.addUser(), CLIENT_ID, "browser")

        fixture.clock.advance(11.minutes)
        assertNull(fixture.sessionService.authenticate(tokens.accessToken, CLIENT_ID))
    }

    @Test
    fun リフレッシュトークンは使うと作り直され古いものは通らない() {
        val fixture = TestFixture()
        val tokens = fixture.sessionService.create(fixture.addUser(), CLIENT_ID, "browser")

        val refreshed = assertNotNull(fixture.sessionService.refresh(tokens.refreshToken, CLIENT_ID))
        assertEquals(tokens.sessionId, refreshed.sessionId)
        assertNull(fixture.sessionService.refresh(tokens.refreshToken, CLIENT_ID))
        assertNull(fixture.sessionService.refresh(refreshed.refreshToken, "other"))
        assertNotNull(fixture.sessionService.refresh(refreshed.refreshToken, CLIENT_ID))
    }

    @Test
    fun リフレッシュトークンは期限を過ぎると通らない() {
        val fixture = TestFixture()
        val tokens = fixture.sessionService.create(fixture.addUser(), CLIENT_ID, "browser")

        fixture.clock.advance(31.days)
        assertNull(fixture.sessionService.refresh(tokens.refreshToken, CLIENT_ID))
    }

    @Test
    fun セッションを消すとアクセストークンも通らない() {
        val fixture = TestFixture()
        val userId = fixture.addUser()
        val tokens = fixture.sessionService.create(userId, CLIENT_ID, "browser")

        assertEquals(true, fixture.sessionService.delete(userId, tokens.sessionId))
        assertNull(fixture.sessionService.authenticate(tokens.accessToken, CLIENT_ID))
        assertNull(fixture.sessionService.refresh(tokens.refreshToken, CLIENT_ID))
    }

    @Test
    fun ログアウトでセッションが消える() {
        val fixture = TestFixture()
        val userId = fixture.addUser()
        val tokens = fixture.sessionService.create(userId, CLIENT_ID, "browser")

        fixture.sessionService.logout(tokens.refreshToken, CLIENT_ID)
        assertEquals(listOf(), fixture.sessionService.sessions(userId))
    }

    @Test
    fun 他人のセッションは消せず名前も変えられない() {
        val fixture = TestFixture()
        val alice = fixture.addUser("alice")
        val bob = fixture.addUser("bob")
        val tokens = fixture.sessionService.create(alice, CLIENT_ID, "browser")

        assertEquals(false, fixture.sessionService.delete(bob, tokens.sessionId))
        assertEquals(SessionService.RenameResult.NotFound, fixture.sessionService.rename(bob, tokens.sessionId, "renamed"))
        assertEquals(SessionService.RenameResult.InvalidName, fixture.sessionService.rename(alice, tokens.sessionId, " "))
        assertEquals(SessionService.RenameResult.Success, fixture.sessionService.rename(alice, tokens.sessionId, "renamed"))
        assertEquals("renamed", fixture.sessionService.sessions(alice).single().name)
    }

    private companion object {
        const val CLIENT_ID = "kake-bo"
    }
}
