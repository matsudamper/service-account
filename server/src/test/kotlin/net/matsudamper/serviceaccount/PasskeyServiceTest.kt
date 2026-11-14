package net.matsudamper.serviceaccount

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import net.matsudamper.serviceaccount.logic.PasskeyService

class PasskeyServiceTest {
    @Test
    fun 読めない登録の応答は受け付けない() {
        val fixture = TestFixture()
        val userId = fixture.addUser()

        listOf("{}", "not json", """{"id":"AA","rawId":"AA","type":"public-key","response":{}}""").forEach { credentialJson ->
            assertEquals(PasskeyService.RegistrationResult.NotAccepted, fixture.passkeyService.register(userId, "key", credentialJson))
        }
    }

    @Test
    fun 読めないログインの応答は受け付けない() {
        val fixture = TestFixture()

        listOf("{}", "not json", """{"id":"AA","rawId":"AA","type":"public-key","response":{}}""").forEach { credentialJson ->
            assertNull(fixture.passkeyService.login(credentialJson))
        }
    }

    @Test
    fun 署名回数は検証に使った値のままのときだけ更新する() {
        val fixture = TestFixture()
        val userId = fixture.addUser()
        fixture.passkeyRepository.add(userId, "credential", byteArrayOf(1), 10, "key", Instant.EPOCH)

        assertTrue(fixture.passkeyRepository.updateSignCount("credential", expectedSignCount = 10, signCount = 12, usedAt = Instant.EPOCH))
        assertFalse(fixture.passkeyRepository.updateSignCount("credential", expectedSignCount = 10, signCount = 11, usedAt = Instant.EPOCH))
        assertEquals(12, fixture.passkeyRepository.find("credential")?.signCount)
    }
}
