rootProject.name = "heidi-kmp"
enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    fun RepositoryHandler.ubique() = maven {
        name = "ubique"
        val ubiqueMavenUrl = System.getenv("UB_ARTIFACTORY_URL_ANDROID")
            ?: System.getenv("ARTIFACTORY_URL_ANDROID")
            ?: extra["ubiqueMavenUrl"] as? String
            ?: ""
        val ubiqueMavenUser = System.getenv("UB_ARTIFACTORY_USER")
            ?: System.getenv("ARTIFACTORY_USER_NAME")
            ?: extra["ubiqueMavenUser"] as? String
            ?: ""
        val ubiqueMavenPass = System.getenv("UB_ARTIFACTORY_PASSWORD")
            ?: System.getenv("ARTIFACTORY_API_KEY")
            ?: extra["ubiqueMavenPass"] as? String
            ?: ""
        url = uri(ubiqueMavenUrl)
        credentials {
            username = ubiqueMavenUser
            password = ubiqueMavenPass
        }
        authentication {
            create<BasicAuthentication>("basic")
            create<DigestAuthentication>("digest")
        }
        content {
            includeGroupAndSubgroups("ch.ubique")
        }
    }

    repositories {
        ubique()
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
            ubique()
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

