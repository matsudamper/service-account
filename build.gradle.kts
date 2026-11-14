import org.jlleitschuh.gradle.ktlint.KtlintExtension

plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.protobuf) apply false
    alias(libs.plugins.graalvm.native) apply false
    alias(libs.plugins.ktlint) apply false
}

// version catalog のアクセサは allprojects の中からは引けないので、ここで取り出しておく
val ktlintVersion = libs.versions.ktlint.get()

allprojects {
    group = "net.matsudamper.serviceaccount"

    apply(plugin = "org.jlleitschuh.gradle.ktlint")

    configure<KtlintExtension> {
        version.set(ktlintVersion)

        filter {
            exclude { element -> element.file.invariantSeparatorsPath.contains("/build/generated/") }
        }
    }
}

// 接続ライブラリ（proto と client）を maven.matsudamper.net に公開する
subprojects {
    plugins.withId("maven-publish") {
        configure<JavaPluginExtension> {
            withSourcesJar()
        }

        configure<PublishingExtension> {
            publications {
                create<MavenPublication>("maven") {
                    from(components["java"])
                    pom {
                        name.set("service-account ${project.name}")
                        url.set("https://github.com/matsudamper/service-account")
                        scm {
                            url.set("https://github.com/matsudamper/service-account")
                            connection.set("scm:git:https://github.com/matsudamper/service-account.git")
                        }
                    }
                }
            }
            repositories {
                maven {
                    name = "MatsudamperMaven"
                    url = uri("https://maven.matsudamper.net/releases")
                    credentials {
                        username = providers.environmentVariable("MAVEN_MATSUDAMPER_USERNAME").orNull
                        password = providers.environmentVariable("MAVEN_MATSUDAMPER_TOKEN").orNull
                    }
                }
            }
        }
    }
}
