package net.matsudamper.serviceaccount

import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import net.matsudamper.serviceaccount.client.AndroidApp
import net.matsudamper.serviceaccount.web.WebDependencies
import net.matsudamper.serviceaccount.web.webModule

class WebModuleTest {
    private val fixture = TestFixture()

    @Test
    fun パスワードでログインするとアカウントトークンとログイントークンを返す() =
        webTest {
            val userId = fixture.addUser()
            val response = postJson("/api/login/password", """{"username":"alice","password":"${TestFixture.PASSWORD}","clientId":"${TestFixture.CLIENT_ID}"}""")
            assertEquals(HttpStatusCode.OK, response.status)
            val body = response.json()

            val loginToken = body.getValue("loginToken").jsonPrimitive.content
            assertEquals(userId, fixture.tokenService.verifyLoginToken(loginToken, TestFixture.CLIENT_ID)?.userId)
            val accountToken = body.getValue("accountToken").jsonPrimitive.content
            assertEquals(userId, fixture.tokenService.verifyAccountToken(accountToken)?.userId)
        }

    @Test
    fun パスワードが違えば401を返す() =
        webTest {
            fixture.addUser()
            val response = postJson("/api/login/password", """{"username":"alice","password":"wrong-password-wrong-password"}""")
            assertEquals(HttpStatusCode.Unauthorized, response.status)
            assertEquals("not_accepted", response.json().getValue("error").jsonPrimitive.content)
        }

    @Test
    fun 登録されていないクライアントのログイントークンは発行しない() =
        webTest {
            fixture.addUser()
            val response = postJson("/api/login/password", """{"username":"alice","password":"${TestFixture.PASSWORD}","clientId":"unknown"}""")
            assertEquals(HttpStatusCode.BadRequest, response.status)
        }

    @Test
    fun アカウントトークンが無ければアカウントを操作できない() =
        webTest {
            fixture.addUser()
            assertEquals(HttpStatusCode.Unauthorized, client.get("/api/account").status)
            val loginToken = fixture.tokenService.issueLoginToken(fixture.userRepository.findByUsername("alice")!!.id, "alice", TestFixture.CLIENT_ID)
            val withLoginToken = client.get("/api/account") { header(HttpHeaders.Authorization, "Bearer ${loginToken.token}") }
            assertEquals(HttpStatusCode.Unauthorized, withLoginToken.status)
        }

    @Test
    fun アカウントトークンでパスワードを変えられる() =
        webTest {
            val userId = fixture.addUser()
            val token = fixture.tokenService.issueAccountToken(userId, "alice").token

            val account = client.get("/api/account") { header(HttpHeaders.Authorization, "Bearer $token") }.json()
            assertEquals("alice", account.getValue("username").jsonPrimitive.content)

            val invalid =
                client.put("/api/account/password") {
                    header(HttpHeaders.Authorization, "Bearer $token")
                    contentType(ContentType.Application.Json)
                    setBody("""{"newPassword":"short"}""")
                }
            assertEquals(HttpStatusCode.BadRequest, invalid.status)

            val changed =
                client.put("/api/account/password") {
                    header(HttpHeaders.Authorization, "Bearer $token")
                    contentType(ContentType.Application.Json)
                    setBody("""{"newPassword":"another-correct-password"}""")
                }
            assertEquals(HttpStatusCode.NoContent, changed.status)

            val deleted = client.delete("/api/account/password") { header(HttpHeaders.Authorization, "Bearer $token") }
            assertEquals(HttpStatusCode.Conflict, deleted.status)
        }

    @Test
    fun ログイン画面からの認可でredirect_uriに認可コードを付けて戻す() =
        webTest {
            val userId = fixture.addUser()
            val page = client.get("/authorize?" + authorizeQuery(TestFixture.REDIRECT_URI))
            assertEquals(HttpStatusCode.OK, page.status)
            assertTrue(page.bodyAsText().contains("data-authorize-request"))

            val token = fixture.tokenService.issueAccountToken(userId, "alice").token
            val response =
                client.post("/api/authorize") {
                    header(HttpHeaders.Authorization, "Bearer $token")
                    contentType(ContentType.Application.Json)
                    setBody(
                        """{"responseType":"code","clientId":"${TestFixture.CLIENT_ID}","redirectUri":"${TestFixture.REDIRECT_URI}","state":"s","codeChallenge":"${AuthorizationServiceTest.CHALLENGE}","codeChallengeMethod":"S256"}""",
                    )
                }
            assertEquals(HttpStatusCode.OK, response.status)
            val redirectUrl = URI(response.json().getValue("redirectUrl").jsonPrimitive.content)
            val code = redirectUrl.query.split('&').first { it.startsWith("code=") }.removePrefix("code=")

            val issued = assertNotNull(fixture.authorizationService.exchange(TestFixture.CLIENT_ID, code, TestFixture.REDIRECT_URI, AuthorizationServiceTest.VERIFIER))
            assertEquals(userId, fixture.tokenService.verifyLoginToken(issued.token, TestFixture.CLIENT_ID)?.userId)
        }

    @Test
    fun 登録されていないredirect_uriならログイン画面を出さない() =
        webTest {
            val page = client.get("/authorize?" + authorizeQuery("https://evil.example.net/callback"))
            assertEquals(HttpStatusCode.BadRequest, page.status)
            assertEquals(null, page.headers[HttpHeaders.Location])
        }

    @Test
    fun 画面にはCSPを付ける() =
        webTest {
            val page = client.get("/account")
            assertTrue(page.headers["Content-Security-Policy"].orEmpty().contains("frame-ancestors 'none'"))
            assertTrue(page.headers["Content-Security-Policy"].orEmpty().contains("script-src 'self'"))
        }

    @Test
    fun assetlinksにAndroidアプリを載せる() =
        webTest {
            val body = Json.parseToJsonElement(client.get("/.well-known/assetlinks.json").bodyAsText()).jsonArray
            val target = body.single().jsonObject.getValue("target").jsonObject
            assertEquals("net.matsudamper.money", target.getValue("package_name").jsonPrimitive.content)
        }

    private fun authorizeQuery(redirectUri: String): String =
        listOf(
            "response_type" to "code",
            "client_id" to TestFixture.CLIENT_ID,
            "redirect_uri" to redirectUri,
            "state" to "s",
            "code_challenge" to AuthorizationServiceTest.CHALLENGE,
            "code_challenge_method" to "S256",
        ).joinToString("&") { (name, value) -> "$name=${java.net.URLEncoder.encode(value, Charsets.UTF_8)}" }

    private fun webTest(block: suspend ApplicationTestBuilder.() -> Unit) =
        testApplication {
            application {
                webModule(
                    WebDependencies(
                        clientRegistry = fixture.clientRegistry,
                        androidApps = listOf(AndroidApp("net.matsudamper.money", listOf(List(32) { "AB" }.joinToString(":")))),
                        userRepository = fixture.userRepository,
                        passwordService = fixture.passwordService,
                        passkeyService = fixture.passkeyService,
                        authorizationService = fixture.authorizationService,
                        tokenService = fixture.tokenService,
                        trustCfConnectingIp = false,
                    ),
                )
            }
            block()
        }

    private suspend fun ApplicationTestBuilder.postJson(
        path: String,
        body: String,
    ): HttpResponse =
        client.post(path) {
            contentType(ContentType.Application.Json)
            setBody(body)
        }

    private suspend fun HttpResponse.json(): JsonObject = Json.parseToJsonElement(bodyAsText()).jsonObject
}
