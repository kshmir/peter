pluginManagement {
    includeBuild("build-logic")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "Peter"

include(":app")
include(":core")
include(":ui")
include(":feature:home")
include(":feature:admin")
include(":feature:contacts")
include(":feature:setup")
