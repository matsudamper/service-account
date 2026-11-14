package net.matsudamper.serviceaccount.graalvm

import java.io.File
import java.util.jar.JarFile
import com.webauthn4j.WebAuthnManager
import org.graalvm.nativeimage.hosted.Feature
import org.graalvm.nativeimage.hosted.RuntimeReflection

/**
 * webauthn4j は応答の JSON と CBOR を Jackson のリフレクションで読む。
 * 読む型を数え上げると版を上げるたびに漏れるので、ビルド時に jar の中のクラスをすべて登録する
 */
class WebAuthn4jReflectionFeature : Feature {
    override fun beforeAnalysis(access: Feature.BeforeAnalysisAccess) {
        val classNames = webAuthn4jClassNames()
        check(classNames.isNotEmpty()) { "webauthn4j のクラスが 1 つも見つからない。jar の場所を引けていない" }
        classNames.forEach(::register)
    }

    private fun webAuthn4jClassNames(): List<String> {
        val jar = File(WebAuthnManager::class.java.protectionDomain.codeSource.location.toURI())
        return JarFile(jar).use { file ->
            file
                .entries()
                .asSequence()
                .map { it.name }
                .filter { it.startsWith(PACKAGE_PATH) && it.endsWith(CLASS_SUFFIX) }
                .map { it.removeSuffix(CLASS_SUFFIX).replace('/', '.') }
                .toList()
        }
    }

    private fun register(className: String) {
        val clazz = Class.forName(className, false, WebAuthn4jReflectionFeature::class.java.classLoader)

        RuntimeReflection.register(clazz)
        RuntimeReflection.register(*clazz.declaredConstructors)
        RuntimeReflection.register(*clazz.declaredMethods)
        RuntimeReflection.register(*clazz.declaredFields)
    }

    private companion object {
        const val PACKAGE_PATH = "com/webauthn4j/"
        const val CLASS_SUFFIX = ".class"
    }
}
