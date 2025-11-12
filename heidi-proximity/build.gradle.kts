plugins {
	alias(libs.plugins.kotlin.multiplatform)
	alias(libs.plugins.android.library)
	alias(libs.plugins.skie)
	alias(libs.plugins.vanniktech.publish)
}

kotlin {
	compilerOptions {
		freeCompilerArgs.add("-Xexpect-actual-classes")
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
	).forEach {
		it.binaries.framework {
			baseName = "heidi-proximity"
			isStatic = true
		}
	}

	sourceSets {
		all {
			languageSettings.optIn("kotlin.uuid.ExperimentalUuidApi")
		}

		commonMain.dependencies {
			implementation(project(":heidi-util"))
			implementation(project(":heidi-crypto"))
			implementation(libs.kotlin.coroutines)
			implementation(libs.koin.core)
			implementation(libs.kotlin.serialization)
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
	namespace = "ch.ubique.heidi.proximity"
	compileSdk = libs.versions.android.compileSdk.get().toInt()

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

mavenPublishing {
	coordinates(project.group.toString(), property("ARTIFACT_ID").toString(), project.version.toString())
	publishToMavenCentral(true)
	signAllPublications()
}