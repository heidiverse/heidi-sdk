plugins {
	alias(libs.plugins.kotlin.multiplatform)
	alias(libs.plugins.kotlin.atomicfu)
	alias(libs.plugins.kotlin.serialization)
	alias(libs.plugins.compose.multiplatform)
	alias(libs.plugins.compose.compiler)
	alias(libs.plugins.android.library)
	alias(libs.plugins.skie)
	alias(libs.plugins.vanniktech.publish)
}

kotlin {
	compilerOptions {
		freeCompilerArgs.add("-Xexpect-actual-classes")
	}

	jvmToolchain(17)

	jvm()

	androidTarget {
		publishLibraryVariants = listOf("release")
	}

	listOf(
		iosX64(),
		iosArm64(),
		iosSimulatorArm64()
	).forEach { iosTarget ->
		iosTarget.binaries.framework {
			baseName = "heidi-visualization"
			isStatic = true
		}

		iosTarget.binaries.all {
			freeCompilerArgs += "-Xallocator=mimalloc"
		}
	}

	sourceSets {
		commonMain.dependencies {
			implementation(project(":heidi-util"))
			implementation(project(":heidi-credentials"))
			implementation(project(":heidi-crypto"))

			implementation(libs.kotlin.coroutines)
			implementation(libs.kotlin.datetime)
			implementation(libs.kotlin.serialization)

			implementation(libs.koin.core)

			// Compose Resources (currently only used for tests, but doesn't work in commonTest)
			// See: https://youtrack.jetbrains.com/issue/CMP-4442
			implementation(compose.runtime)
			implementation(compose.components.resources)
		}

		commonTest.dependencies {
			implementation(libs.kotlin.test)
		}

		androidMain.dependencies {
			implementation(libs.koin.android)
		}
	}
}

android {
	namespace = "ch.ubique.heidi.visualization"
	compileSdk = libs.versions.android.compileSdk.get().toInt()

	ndkVersion = libs.versions.android.ndk.get()

	defaultConfig {
		minSdk = libs.versions.android.minSdk.get().toInt()
	}

	compileOptions {
		sourceCompatibility = JavaVersion.VERSION_17
		targetCompatibility = JavaVersion.VERSION_17
	}
}

skie {
	analytics {
		enabled = false
		disableUpload = true
	}
}

compose.resources {
	publicResClass = false
	packageOfResClass = "ch.ubique.heidi.visualization"
	generateResClass = always
}

mavenPublishing {
	coordinates(project.group.toString(), property("ARTIFACT_ID").toString(), project.version.toString())
}

publishing {
	repositories {
		maven {
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
		}
	}
}