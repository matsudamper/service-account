package net.matsudamper.serviceaccount.web

import java.util.concurrent.ConcurrentHashMap

internal object StaticResources {
    private val cache = ConcurrentHashMap<String, String>()

    fun text(path: String): String =
        cache.getOrPut(path) {
            checkNotNull(StaticResources::class.java.classLoader.getResourceAsStream(path)) { "$path が無い" }
                .use { it.readBytes().decodeToString() }
        }
}
