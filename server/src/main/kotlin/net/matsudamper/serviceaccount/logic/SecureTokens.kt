package net.matsudamper.serviceaccount.logic

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

object SecureTokens {
    private val random = SecureRandom()
    private val encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()

    /**
     * base64url（パディング無し）
     */
    fun random(sizeBytes: Int): String = encode(ByteArray(sizeBytes).also(random::nextBytes))

    /**
     * 推測できない長さの乱数に使うので salt や反復は要らない
     */
    fun sha256(value: String): String = encode(MessageDigest.getInstance("SHA-256").digest(value.encodeToByteArray()))

    fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)
}
