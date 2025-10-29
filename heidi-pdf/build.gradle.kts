import ch.ubique.uniffi.plugin.extensions.useRustUpLinker

plugins {
	alias(libs.plugins.kotlin.multiplatform)
	alias(libs.plugins.kotlin.atomicfu)
	alias(libs.plugins.android.library)
	alias(libs.plugins.skie)
	alias(libs.plugins.vanniktech.publish)
	alias(libs.plugins.kotlin.serialization)
	alias(libs.plugins.uniffi.plugin)
}

kotlin {
	compilerOptions {
		freeCompilerArgs.add("-Xexpect-actual-classes")
		freeCompilerArgs.add("-Xwhen-guards")
	}

	jvmToolchain(17)

	androidTarget {
		publishLibraryVariants = listOf("release")
	}
	jvm()
	listOf(
		iosX64(),
		iosArm64(),
		iosSimulatorArm64()
	).forEach { iosTarget ->
		iosTarget.binaries.framework {
			baseName = "heidi-pdf"
			isStatic = true
		}

		iosTarget.binaries.all {
			freeCompilerArgs += "-Xallocator=mimalloc"
		}

		iosTarget.compilations.getByName("main") {
			useRustUpLinker()
		}
	}

	sourceSets {
		commonMain.dependencies {
			implementation(libs.kotlin.coroutines)
			implementation(libs.koin.core)
			implementation(libs.kotlin.serialization)
		}

		commonTest.dependencies {
			implementation(libs.kotlin.test)
			implementation(libs.kotlin.serialization)
		}

		androidMain.dependencies {
			implementation(libs.koin.android)
		}
	}
}

android {
	namespace = "ch.ubique.heidi.pdf"
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

uniffi {
	bindgenFromGitTag(
		"https://github.com/UbiqueInnovation/uniffi-kotlin-multiplatform-bindings.git",
		libs.versions.uniffi.bindgen.get()
	)
	generateFromLibrary()
}

cargo {
	packageDirectory = layout.projectDirectory.dir("rust")
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