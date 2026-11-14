package net.matsudamper.serviceaccount.web

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import net.matsudamper.serviceaccount.logic.AuthorizationRequest

/**
 * 画面の HTML。値は data 属性で JavaScript に渡し、inline の script は使わない（CSP で禁止している）
 */
internal object Pages {
    fun authorize(request: AuthorizationRequest): String {
        val requestJson =
            Json.encodeToString(
                buildJsonObject {
                    put("responseType", request.responseType)
                    put("clientId", request.clientId)
                    put("redirectUri", request.redirectUri)
                    request.state?.let { put("state", it) }
                    put("codeChallenge", request.codeChallenge)
                    put("codeChallengeMethod", request.codeChallengeMethod)
                },
            )
        return layout(
            title = "ログイン",
            page = "authorize",
            attributes = """data-authorize-request="${escape(requestJson)}"""",
            body =
            """
                <h1>ログイン</h1>
                <p class="note">${escape(request.clientId)} にログインします</p>
                $LOGIN_FORM
            """.trimIndent(),
        )
    }

    fun account(): String =
        layout(
            title = "アカウント設定",
            page = "account",
            attributes = "",
            body =
            """
                <h1>アカウント設定</h1>
                <section id="login-section">
                  <p class="note">設定を変えるには、もう一度ログインしてください</p>
                  $LOGIN_FORM
                </section>
                <section id="settings-section" hidden>
                  <p>ユーザー名: <strong id="account-username"></strong></p>

                  <h2>パスワード</h2>
                  <p id="password-state"></p>
                  <form id="password-form">
                    <input type="text" id="password-form-username" name="username" autocomplete="username" hidden>
                    <label>新しいパスワード
                      <input type="password" id="new-password" name="new-password" autocomplete="new-password" required>
                    </label>
                    <button type="submit">パスワードを変更する</button>
                  </form>
                  <button type="button" id="delete-password-button" class="danger">パスワードを削除する</button>

                  <h2>パスキー</h2>
                  <ul id="passkey-list"></ul>
                  <form id="passkey-form">
                    <label>名前
                      <input type="text" id="passkey-name" maxlength="64" required>
                    </label>
                    <button type="submit">パスキーを登録する</button>
                  </form>
                </section>
            """.trimIndent(),
        )

    fun error(message: String): String =
        layout(
            title = "エラー",
            page = "error",
            attributes = "",
            body =
            """
                <h1>ログインできません</h1>
                <p>${escape(message)}</p>
            """.trimIndent(),
        )

    private fun layout(
        title: String,
        page: String,
        attributes: String,
        body: String,
    ): String =
        """
        <!doctype html>
        <html lang="ja">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>${escape(title)}</title>
          <link rel="stylesheet" href="/static/style.css">
          <script src="/static/app.js" defer></script>
        </head>
        <body>
          <main id="app" data-page="$page" $attributes>
            $body
            <p id="message" role="alert"></p>
          </main>
        </body>
        </html>
        """.trimIndent()

    private fun escape(value: String): String =
        buildString {
            value.forEach { char ->
                when (char) {
                    '&' -> append("&amp;")
                    '<' -> append("&lt;")
                    '>' -> append("&gt;")
                    '"' -> append("&quot;")
                    '\'' -> append("&#39;")
                    else -> append(char)
                }
            }
        }

    /**
     * パスワードマネージャが拾えるよう autocomplete を付ける。
     * username に webauthn を付けると、対応するブラウザは入力欄の候補にパスキーも出す
     */
    private val LOGIN_FORM =
        """
        <form id="login-form">
          <label>ユーザー名
            <input type="text" id="username" name="username" autocomplete="username webauthn" required>
          </label>
          <label>パスワード
            <input type="password" id="password" name="password" autocomplete="current-password" required>
          </label>
          <button type="submit">ログイン</button>
        </form>
        <button type="button" id="passkey-login-button">パスキーでログイン</button>
        """.trimIndent()
}
