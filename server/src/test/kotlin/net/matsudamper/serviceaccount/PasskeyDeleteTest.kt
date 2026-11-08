package net.matsudamper.serviceaccount

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import net.matsudamper.serviceaccount.db.PasskeyDeleteResult

class PasskeyDeleteTest {
    @Test
    fun パスワードが無いとき最後のパスキーは消さない() {
        val fixture = TestFixture()
        val userId = fixture.addUser()
        fixture.passkeyRepository.add(userId, "example.com", "first", byteArrayOf(1), 0, "first", Instant.EPOCH)
        fixture.passkeyRepository.add(userId, "example.com", "second", byteArrayOf(1), 0, "second", Instant.EPOCH)
        fixture.passwordService.delete(userId)

        assertEquals(PasskeyDeleteResult.Success, fixture.passkeyService.delete(userId, "first"))
        assertEquals(PasskeyDeleteResult.LastLoginMethod, fixture.passkeyService.delete(userId, "second"))
    }

    @Test
    fun 他人のパスキーは消せない() {
        val fixture = TestFixture()
        val alice = fixture.addUser("alice")
        val bob = fixture.addUser("bob")
        fixture.passkeyRepository.add(alice, "example.com", "alice-key", byteArrayOf(1), 0, "key", Instant.EPOCH)

        assertEquals(PasskeyDeleteResult.NotFound, fixture.passkeyService.delete(bob, "alice-key"))
        assertEquals(PasskeyDeleteResult.Success, fixture.passkeyService.delete(alice, "alice-key"))
    }
}
