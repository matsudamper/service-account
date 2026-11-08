package net.matsudamper.serviceaccount.password

object PasswordPolicy {
    val LENGTH_RANGE: IntRange = 20..256

    private val allowedCharacters: Set<Char> =
        buildSet {
            addAll('A'..'Z')
            addAll('a'..'z')
            addAll('0'..'9')
            addAll(listOf('!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '-', '?', '<', '>', ',', '.'))
        }

    fun validate(password: String): PasswordViolations {
        val invalidCharacters = password.filter { it !in allowedCharacters }.toSet().joinToString("")
        return PasswordViolations(
            invalidLength = password.length !in LENGTH_RANGE,
            invalidCharacters = invalidCharacters,
        )
    }
}

data class PasswordViolations(
    val invalidLength: Boolean,
    /**
     * 使えない文字。重複は除く
     */
    val invalidCharacters: String,
) {
    val isValid: Boolean get() = !invalidLength && invalidCharacters.isEmpty()
}
