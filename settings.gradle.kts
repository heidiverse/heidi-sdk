rootProject.name = "heidi-kmp"
enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        gradlePluginPortal()
        mavenCentral()
    }

    dependencyResolutionManagement {
        repositories {
            google()
            mavenCentral()
        }
    }
}

include(":examples:android-verifier")
include(":examples:android-wallet")

include(":heidi-util")
include(":heidi-credentials")
include(":heidi-crypto")
include(":heidi-issuance")
include(":heidi-presentation")
include(":heidi-pdf")
include(":heidi-dcql")
include(":heidi-proximity")
include(":heidi-trust")
include(":heidi-visualization")
include(":heidi-wallet")

