package net.matsudamper.serviceaccount

import java.net.URI
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.minutes
import net.matsudamper.serviceaccount.logic.AuthorizationRequest
import net.matsudamper.serviceaccount.logic.AuthorizationRequestError

class AuthorizationServiceTest {
    @Test
    fun 認可コードをログイントークンに交換できる() {
        val fixture = TestFixture()
        val userId = fixture.addUser()
        val redirectUrl = assertNotNull(fixture.authorizationService.issueCode(request(), userId))

        val query = queryOf(redirectUrl)
        assertEquals("state-value", query["state"])
        assertEquals(true, redirectUrl.startsWith(TestFixture.REDIRECT_URI + "?"))

        val issued = assertNotNull(fixture.authorizationService.exchange(TestFixture.CLIENT_ID, query.getValue("code"), TestFixture.REDIRECT_URI, VERIFIER))
        assertEquals(userId, fixture.tokenService.verifyLoginToken(issued.token, TestFixture.CLIENT_ID)?.userId)
    }

    @Test
    fun 認可コードは1回しか使えない() {
        val fixture = TestFixture()
        val code = issueCode(fixture)

        assertNotNull(fixture.authorizationService.exchange(TestFixture.CLIENT_ID, code, TestFixture.REDIRECT_URI, VERIFIER))
        assertNull(fixture.authorizationService.exchange(TestFixture.CLIENT_ID, code, TestFixture.REDIRECT_URI, VERIFIER))
    }

    @Test
    fun 照合に失敗したコードはもう使えない() {
        val fixture = TestFixture()
        val code = issueCode(fixture)

        assertNull(fixture.authorizationService.exchange(TestFixture.CLIENT_ID, code, TestFixture.REDIRECT_URI, "x".repeat(43)))
        assertNull(fixture.authorizationService.exchange(TestFixture.CLIENT_ID, code, TestFixture.REDIRECT_URI, VERIFIER))
    }

    @Test
    fun 別のクライアントやredirect_uriでは交換できない() {
        val fixture = TestFixture()

        assertNull(fixture.authorizationService.exchange(TestFixture.OTHER_CLIENT_ID, issueCode(fixture), TestFixture.REDIRECT_URI, VERIFIER))
        assertNull(fixture.authorizationService.exchange(TestFixture.CLIENT_ID, issueCode(fixture), "https://money.example.com/other", VERIFIER))
    }

    @Test
    fun 期限切れのコードは交換できない() {
        val fixture = TestFixture()
        val code = issueCode(fixture)

        fixture.clock.advance(2.minutes)
        assertNull(fixture.authorizationService.exchange(TestFixture.CLIENT_ID, code, TestFixture.REDIRECT_URI, VERIFIER))
    }

    @Test
    fun 登録されていないクライアントやredirect_uriは受け付けない() {
        val fixture = TestFixture()

        assertEquals(AuthorizationRequestError.UnknownClient, fixture.authorizationService.validate(request(clientId = "unknown")))
        assertEquals(AuthorizationRequestError.UnregisteredRedirectUri, fixture.authorizationService.validate(request(redirectUri = "https://evil.example.net/callback")))
        assertEquals(AuthorizationRequestError.InvalidCodeChallenge, fixture.authorizationService.validate(request(codeChallengeMethod = "plain")))
        assertNull(fixture.authorizationService.issueCode(request(redirectUri = "https://evil.example.net/callback"), fixture.addUser()))
    }

    private fun issueCode(fixture: TestFixture): String {
        val userId = fixture.userRepository.findByUsername("alice")?.id ?: fixture.addUser()
        return queryOf(assertNotNull(fixture.authorizationService.issueCode(request(), userId))).getValue("code")
    }

    private fun request(
        clientId: String = TestFixture.CLIENT_ID,
        redirectUri: String = TestFixture.REDIRECT_URI,
        codeChallengeMethod: String = "S256",
    ) = AuthorizationRequest(
        responseType = "code",
        clientId = clientId,
        redirectUri = redirectUri,
        state = "state-value",
        codeChallenge = CHALLENGE,
        codeChallengeMethod = codeChallengeMethod,
    )

    private fun queryOf(url: String): Map<String, String> =
        URI(url).query.split('&').associate { parameter ->
            val (name, value) = parameter.split('=', limit = 2)
            name to value
        }

    companion object {
        const val VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        val CHALLENGE: String = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(VERIFIER.encodeToByteArray()))
    }
}
