package net.matsudamper.serviceaccount.cli

import net.matsudamper.serviceaccount.client.ClientRegistry
import net.matsudamper.serviceaccount.logic.SecureTokens
import net.matsudamper.serviceaccount.logic.UserAdminService
import net.matsudamper.serviceaccount.password.PasswordPolicy
import net.matsudamper.serviceaccount.password.PasswordViolations

/**
 * パスワードはシェルの履歴と `ps` に残らないよう標準入力から受ける。照合は入力そのままなので前後の空白は落とさない
 *
 * @return 終了コード
 */
class UserCli(
    private val userAdminService: UserAdminService,
) {
    fun addUser(username: String?): Int {
        if (username.isNullOrBlank()) return fail("ユーザー名を引数で渡すこと")
        val password = readPassword() ?: return fail("パスワードを標準入力に 1 行で渡すこと")
        return when (val result = userAdminService.addUser(username = username, password = password)) {
            is UserAdminService.AddUserResult.Success -> {
                println("追加した: user_id=${result.userId.value}")
                0
            }

            UserAdminService.AddUserResult.AlreadyExists -> fail("同じ名前のユーザーがいる")

            UserAdminService.AddUserResult.InvalidUsername -> fail("ユーザー名は英数字と _ . - の 64 文字以内にすること")

            is UserAdminService.AddUserResult.InvalidPassword -> fail(describe(result.violations))
        }
    }

    fun setPassword(username: String?): Int {
        if (username.isNullOrBlank()) return fail("ユーザー名を引数で渡すこと")
        val password = readPassword() ?: return fail("パスワードを標準入力に 1 行で渡すこと")
        return when (val result = userAdminService.replacePassword(username = username, password = password)) {
            UserAdminService.ReplacePasswordResult.Success -> {
                println("置き換えた")
                0
            }

            UserAdminService.ReplacePasswordResult.UserNotFound -> fail("ユーザーがいない")

            is UserAdminService.ReplacePasswordResult.InvalidPassword -> fail(describe(result.violations))
        }
    }

    private fun readPassword(): String? {
        System.err.println("パスワードを入力してください")
        return readlnOrNull()?.takeIf { it.isNotEmpty() }
    }

    private fun describe(violations: PasswordViolations): String =
        buildList {
            if (violations.invalidLength) add("パスワードは ${PasswordPolicy.LENGTH_RANGE.first}〜${PasswordPolicy.LENGTH_RANGE.last} 文字にすること")
            if (violations.invalidCharacters.isNotEmpty()) add("使えない文字: ${violations.invalidCharacters}")
        }.joinToString("\n")

    private fun fail(message: String): Int {
        System.err.println(message)
        return 1
    }

    companion object {
        private const val CLIENT_SECRET_SIZE_BYTES = 32

        fun printClientSecret() {
            val secret = SecureTokens.random(CLIENT_SECRET_SIZE_BYTES)
            println("secret: $secret")
            println("secretSha256: ${ClientRegistry.hashSecret(secret)}")
        }
    }
}
