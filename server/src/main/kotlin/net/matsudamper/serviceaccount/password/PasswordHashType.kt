package net.matsudamper.serviceaccount.password

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder

/**
 * user_passwords.password_hash_type に [dbValue] を入れる。DB に残るので [dbValue] は変えない
 */
enum class PasswordHashType(
    val dbValue: String,
    val encoder: PasswordEncoder,
) {
    /**
     * 値にパラメーターを含むので、設定を変えても既存の値は照合できる
     */
    Argon2(
        dbValue = "argon2",
        encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(),
    ),
    ;

    companion object {
        val Current: PasswordHashType = Argon2

        fun fromDbValue(dbValue: String): PasswordHashType? = entries.firstOrNull { it.dbValue == dbValue }
    }
}
