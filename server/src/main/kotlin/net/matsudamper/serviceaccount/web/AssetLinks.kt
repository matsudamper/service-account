package net.matsudamper.serviceaccount.web

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import net.matsudamper.serviceaccount.client.AndroidApp

/**
 * Android アプリがこのドメインのパスキーと保存済みパスワードを使えるようにする Digital Asset Links
 */
internal object AssetLinks {
    fun json(androidApps: List<AndroidApp>): String =
        buildJsonArray {
            androidApps.forEach { app ->
                add(
                    buildJsonObject {
                        put("relation", JsonArray(RELATIONS.map(::JsonPrimitive)))
                        put(
                            "target",
                            buildJsonObject {
                                put("namespace", "android_app")
                                put("package_name", app.packageName)
                                put("sha256_cert_fingerprints", JsonArray(app.sha256CertFingerprints.map { JsonPrimitive(it.uppercase()) }))
                            },
                        )
                    },
                )
            }
        }.toString()

    private val RELATIONS =
        listOf(
            "delegate_permission/common.handle_all_urls",
            "delegate_permission/common.get_login_creds",
        )
}
