import java.util.Properties

plugins {
    id("peter.android.application")
    id("peter.android.compose")
    id("peter.android.hilt")
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.play.publisher)
}

play {
    // Upload AAB to internal testing track; promote manually in Play Console
    track.set("internal")
    releaseStatus.set(com.github.triplet.gradle.androidpublisher.ReleaseStatus.COMPLETED)
    defaultToAppBundles.set(true)
    // Service account JSON provided via PLAY_SERVICE_ACCOUNT_JSON env var or file
    val saFile = rootProject.file("play-service-account.json")
    if (saFile.exists()) {
        serviceAccountCredentials.set(saFile)
    }
}

android {
    namespace = "com.peter.app"

    val versionProps = Properties()
    rootProject.file("version.properties").inputStream().use { versionProps.load(it) }

    defaultConfig {
        applicationId = "com.peter.app"
        versionCode = (versionProps["versionCode"] as String).trim().toInt()
        versionName = (versionProps["versionName"] as? String)?.trim() ?: "0.0.$versionCode"
    }

    val keystorePropertiesFile = rootProject.file("keystore.properties")
    if (keystorePropertiesFile.exists()) {
        val keystoreProperties = Properties()
        keystoreProperties.load(keystorePropertiesFile.inputStream())

        signingConfigs {
            create("release") {
                storeFile = rootProject.file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }

        buildTypes {
            release {
                isMinifyEnabled = true
                isShrinkResources = true
                proguardFiles(
                    getDefaultProguardFile("proguard-android-optimize.txt"),
                    "proguard-rules.pro"
                )
                signingConfig = signingConfigs.getByName("release")
            }
        }
    } else {
        buildTypes {
            release {
                isMinifyEnabled = true
                isShrinkResources = true
                proguardFiles(
                    getDefaultProguardFile("proguard-android-optimize.txt"),
                    "proguard-rules.pro"
                )
            }
        }
    }
}

dependencies {
    implementation(project(":core"))
    implementation(project(":ui"))
    implementation(project(":feature:home"))
    implementation(project(":feature:admin"))
    implementation(project(":feature:contacts"))
    implementation(project(":feature:setup"))

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.compose.ui.tooling.preview)
    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.activity.compose)
    implementation(libs.navigation.compose)
    implementation(libs.hilt.navigation.compose)
    implementation(libs.lifecycle.runtime.compose)
    implementation(libs.core.ktx)
    implementation(libs.core.splashscreen)
    implementation(libs.kotlinx.serialization.json)

    // Needed for Hilt KSP to resolve types from :core providers
    implementation(libs.room.runtime)
    implementation(libs.datastore.preferences)
}
