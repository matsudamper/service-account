package net.matsudamper.serviceaccount

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import net.matsudamper.serviceaccount.client.RegisteredClient
import net.matsudamper.serviceaccount.logic.PasskeyService
import net.matsudamper.serviceaccount.passkey.PasskeyRelyingParty

class PasskeyServiceTest {
    private val client = RegisteredClient("kake-bo", "unused", PasskeyRelyingParty("example.com", setOf("https://example.com")))

    @Test
    fun 読めない登録の応答は受け付けない() {
        val fixture = TestFixture()
        val userId = fixture.addUser()

        listOf("{}", "not json", """{"id":"AA","rawId":"AA","type":"public-key","response":{}}""").forEach { credentialJson ->
            assertEquals(PasskeyService.RegistrationResult.NotAccepted, fixture.passkeyService.register(client, userId, "key", credentialJson))
        }
    }

    @Test
    fun 読めないログインの応答は受け付けない() {
        val fixture = TestFixture()

        listOf("{}", "not json", """{"id":"AA","rawId":"AA","type":"public-key","response":{}}""").forEach { credentialJson ->
            assertNull(fixture.passkeyService.login(client, credentialJson))
        }
    }
}
