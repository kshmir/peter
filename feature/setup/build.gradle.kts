plugins {
    id("peter.android.library")
    id("peter.android.compose")
    id("peter.android.hilt")
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.peter.app.feature.setup"
}

dependencies {
    implementation(project(":core"))
    implementation(project(":ui"))

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.compose.ui.tooling.preview)
    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.navigation.compose)
    implementation(libs.hilt.navigation.compose)
    implementation(libs.lifecycle.viewmodel.compose)
    implementation(libs.lifecycle.runtime.compose)
    implementation(libs.kotlinx.serialization.json)
}
