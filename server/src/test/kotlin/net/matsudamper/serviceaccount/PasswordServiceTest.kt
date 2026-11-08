package net.matsudamper.serviceaccount

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.minutes
import net.matsudamper.serviceaccount.logic.PasswordLoginResult
import net.matsudamper.serviceaccount.logic.PasswordService

class PasswordServiceTest {
    @Test
    fun 正しいパスワードならログインできる() {
        val fixture = TestFixture()
        val userId = fixture.addUser()

        assertEquals(PasswordLoginResult.Success(userId), fixture.passwordService.login("alice", TestFixture.PASSWORD, CLIENT_IP))
    }

    @Test
    fun 違うパスワードやいないユーザーは通さない() {
        val fixture = TestFixture()
        fixture.addUser()

        assertEquals(PasswordLoginResult.NotAccepted, fixture.passwordService.login("alice", "wrong-password-wrong-password", CLIENT_IP))
        assertEquals(PasswordLoginResult.NotAccepted, fixture.passwordService.login("bob", TestFixture.PASSWORD, CLIENT_IP))
    }

    @Test
    fun 失敗が上限に達した送信元は締め出し期限まで照合しない() {
        val fixture = TestFixture(maxLoginFailures = 3)
        fixture.addUser()
        repeat(3) { fixture.passwordService.login("alice", "wrong-password-wrong-password", CLIENT_IP) }

        assertEquals(PasswordLoginResult.TooManyAttempts, fixture.passwordService.login("alice", TestFixture.PASSWORD, CLIENT_IP))
        assertTrue(fixture.passwordService.login("alice", TestFixture.PASSWORD, "192.0.2.2") is PasswordLoginResult.Success)

        fixture.clock.advance(16.minutes)
        assertTrue(fixture.passwordService.login("alice", TestFixture.PASSWORD, CLIENT_IP) is PasswordLoginResult.Success)
    }

    @Test
    fun 成功するとそのユーザー名の失敗だけ消える() {
        val fixture = TestFixture(maxLoginFailures = 3)
        fixture.addUser()
        fixture.passwordService.login("alice", "wrong-password-wrong-password", CLIENT_IP)
        fixture.passwordService.login("bob", "wrong-password-wrong-password", CLIENT_IP)
        fixture.passwordService.login("alice", TestFixture.PASSWORD, CLIENT_IP)

        // alice の分は消え、bob の分だけが残る。bob の失敗が上限に達すると alice も締め出される
        fixture.passwordService.login("bob", "wrong-password-wrong-password", CLIENT_IP)
        assertTrue(fixture.passwordService.login("alice", TestFixture.PASSWORD, CLIENT_IP) is PasswordLoginResult.Success)
        fixture.passwordService.login("bob", "wrong-password-wrong-password", CLIENT_IP)
        assertEquals(PasswordLoginResult.TooManyAttempts, fixture.passwordService.login("alice", TestFixture.PASSWORD, CLIENT_IP))
    }

    @Test
    fun パスキーが無ければパスワードを消さない() {
        val fixture = TestFixture()
        val userId = fixture.addUser()

        assertEquals(PasswordService.DeletePasswordResult.NoPasskey, fixture.passwordService.delete(userId))
        assertTrue(fixture.passwordService.hasPassword(userId))

        fixture.passkeyRepository.add(userId, "example.com", "credential", byteArrayOf(1), 0, "key", Instant.EPOCH)
        assertEquals(PasswordService.DeletePasswordResult.Success, fixture.passwordService.delete(userId))
        assertFalse(fixture.passwordService.hasPassword(userId))
    }

    @Test
    fun 規則に合わないパスワードには変えない() {
        val fixture = TestFixture()
        val userId = fixture.addUser()

        val violations = fixture.passwordService.change(userId, "shortあ")
        assertTrue(violations.invalidLength)
        assertEquals("あ", violations.invalidCharacters)

        val newPassword = "another-correct-password"
        assertTrue(fixture.passwordService.change(userId, newPassword).isValid)
        assertEquals(PasswordLoginResult.Success(userId), fixture.passwordService.login("alice", newPassword, CLIENT_IP))
    }

    private companion object {
        const val CLIENT_IP = "192.0.2.1"
    }
}
