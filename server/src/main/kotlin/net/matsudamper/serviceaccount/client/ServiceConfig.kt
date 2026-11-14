package net.matsudamper.serviceaccount.client

import java.security.MessageDigest
import java.util.Base64
import java.util.HexFormat
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * 設定ファイル（SERVICE_ACCOUNT_CONFIG_FILE）の中身
 */
class ServiceConfig(
    val clientRegistry: ClientRegistry,
    val androidApps: List<AndroidApp>,
) {
    companion object {
        fun parse(json: String): ServiceConfig {
            val file = Json.decodeFromString<ConfigFile>(json)
            return ServiceConfig(
                clientRegistry =
                ClientRegistry(
                    file.clients.map { client ->
                        RegisteredClient(
                            id = client.id,
                            secretSha256 = client.secretSha256,
                            redirectUris = client.redirectUris.toSet(),
                        )
                    },
                ),
                androidApps =
                file.androidApps.map { app ->
                    AndroidApp(packageName = app.packageName, sha256CertFingerprints = app.sha256CertFingerprints)
                },
            )
        }
    }
}

/**
 * このサービスを使う各サービス。シークレットは SHA-256 のハッシュだけを持つ
 */
class ClientRegistry(
    clients: List<RegisteredClient>,
) {
    private val clientsById: Map<String, RegisteredClient> = clients.associateBy { it.id }

    init {
        require(clientsById.size == clients.size) { "クライアントの id が重複している" }
    }

    fun find(clientId: String): RegisteredClient? = clientsById[clientId]

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
    }
}

class RegisteredClient(
    val id: String,
    val secretSha256: String,
    /**
     * 認可コードを返してよい URI。完全一致で比べる
     */
    val redirectUris: Set<String>,
)

/**
 * パスキーとパスワードをこのサービスのドメインと共有する Android アプリ。assetlinks.json に載せる
 *
 * @param sha256CertFingerprints 署名証明書の SHA-256。`AA:BB:...` の形
 */
class AndroidApp(
    val packageName: String,
    val sha256CertFingerprints: List<String>,
) {
    /**
     * Credential Manager が clientDataJSON に入れる origin
     */
    val passkeyOrigins: List<String> =
        sha256CertFingerprints.map { fingerprint ->
            val bytes = HexFormat.ofDelimiter(":").parseHex(fingerprint.uppercase())
            require(bytes.size == SHA256_BYTES) { "$packageName の署名証明書の SHA-256 が 32 バイトではない: $fingerprint" }
            "android:apk-key-hash:" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        }

    private companion object {
        const val SHA256_BYTES = 32
    }
}

@Serializable
private class ConfigFile(
    val clients: List<ClientEntry>,
    val androidApps: List<AndroidAppEntry> = listOf(),
)

@Serializable
private class ClientEntry(
    val id: String,
    val secretSha256: String,
    val redirectUris: List<String> = listOf(),
)

@Serializable
private class AndroidAppEntry(
    val packageName: String,
    val sha256CertFingerprints: List<String>,
)
