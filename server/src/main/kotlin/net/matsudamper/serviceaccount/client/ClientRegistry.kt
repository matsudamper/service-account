package net.matsudamper.serviceaccount.client

import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.matsudamper.serviceaccount.passkey.PasskeyRelyingParty

/**
 * このサービスを呼び出す各サービス。シークレットは SHA-256 のハッシュだけを持つ
 */
class ClientRegistry(
    clients: List<RegisteredClient>,
) {
    private val clientsById: Map<String, RegisteredClient> = clients.associateBy { it.id }

    init {
        require(clientsById.size == clients.size) { "クライアントの id が重複している" }
    }

    /**
     * 存在しない id でも同じだけ計算して、応答時間で id の有無を分からなくする
     */
    fun authenticate(
        clientId: String,
        secret: String,
    ): RegisteredClient? {
        val client = clientsById[clientId]
        val expected = client?.secretSha256 ?: DUMMY_HASH
        val matched = MessageDigest.isEqual(hashSecret(secret).encodeToByteArray(), expected.encodeToByteArray())
        return client?.takeIf { matched }
    }

    companion object {
        private val DUMMY_HASH = hashSecret("dummy-secret")

        fun hashSecret(secret: String): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(secret.encodeToByteArray()))

        fun parse(json: String): ClientRegistry {
            val file = Json.decodeFromString<ClientsFile>(json)
            return ClientRegistry(
                file.clients.map { client ->
                    RegisteredClient(
                        id = client.id,
                        secretSha256 = client.secretSha256,
                        relyingParty = PasskeyRelyingParty(id = client.passkey.rpId, origins = client.passkey.origins.toSet()),
                    )
                },
            )
        }
    }
}

class RegisteredClient(
    val id: String,
    val secretSha256: String,
    /**
     * 同じ RP ID のクライアント同士はパスキーを共有する
     */
    val relyingParty: PasskeyRelyingParty,
)

@Serializable
private class ClientsFile(
    val clients: List<ClientEntry>,
)

@Serializable
private class ClientEntry(
    val id: String,
    val secretSha256: String,
    val passkey: PasskeyEntry,
)

@Serializable
private class PasskeyEntry(
    val rpId: String,
    val origins: List<String>,
)
