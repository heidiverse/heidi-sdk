rootProject.name = "kapun-sdk"
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

include(":kapun-util")
include(":kapun-credentials")
include(":kapun-crypto")
include(":kapun-issuance")
include(":kapun-presentation")
include(":kapun-pdf")
include(":kapun-dcql")
include(":kapun-proximity")
include(":kapun-trust")
include(":kapun-visualization")
include(":kapun-wallet")
