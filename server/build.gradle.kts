plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.graalvm.native)
    application
}

dependencies {
    implementation(project(":proto"))
    implementation(libs.grpc.netty.shaded)
    implementation(libs.grpc.services)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.sqlite.jdbc)
    implementation(libs.webauthn4j.core)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.spring.security.crypto)
    implementation(libs.bouncycastle.bcprov)
    // spring-security-crypto のログ出力（commons-logging）を解決する
    runtimeOnly(libs.spring.core)
    implementation(libs.slf4j.api)
    runtimeOnly(libs.slf4j.simple)
    compileOnly(libs.graalvm.nativeimage)

    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.grpc.inprocess)
}

kotlin {
    jvmToolchain(25)
}

application {
    mainClass.set("net.matsudamper.serviceaccount.MainKt")
    applicationName = "service-account"
}

tasks.test {
    useJUnitPlatform()
}

graalvmNative {
    // GraalVM を JAVA_HOME に置いた環境（Dockerfile のビルドステージ）で native-image を探す
    toolchainDetection.set(false)
    metadataRepository {
        enabled.set(true)
    }
    binaries {
        named("main") {
            imageName.set("service-account")
            buildArgs.add("--no-fallback")
            // sqlite-jdbc が System.load するので、起動のたびに警告が出ないよう許可する
            buildArgs.add("--enable-native-access=ALL-UNNAMED")
            buildArgs.add("--features=net.matsudamper.serviceaccount.graalvm.WebAuthn4jReflectionFeature")
            buildArgs.add("-H:IncludeResources=db/migration/.*\\.sql")
        }
    }
}
