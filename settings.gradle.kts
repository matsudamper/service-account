rootProject.name = "service-account"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

// settings.gradle.kts の plugins ブロックが評価される時点では version catalog のアクセサが無い
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

include(":proto")
include(":server")
