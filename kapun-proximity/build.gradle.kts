plugins {
	alias(libs.plugins.kotlin.multiplatform)
	alias(libs.plugins.android.kotlin.multiplatform.library)
	alias(libs.plugins.skie)
	alias(libs.plugins.vanniktech.publish)
	alias(libs.plugins.kotlin.serialization)
}

kotlin {
	compilerOptions {
		freeCompilerArgs.add("-Xexpect-actual-classes")
	}

	jvmToolchain(17)

	android {
		namespace = "org.kapunsdk.proximity"
		compileSdk = libs.versions.android.compileSdk.get().toInt()
		minSdk = libs.versions.android.minSdk.get().toInt()
	}
	jvm()

	listOf(

		iosArm64(),
		iosSimulatorArm64()
	).forEach {
		it.binaries.framework {
			baseName = "kapun-proximity"
			isStatic = true
		}
	}

	sourceSets {
		all {
			languageSettings.optIn("kotlin.uuid.ExperimentalUuidApi")
		}

		commonMain.dependencies {
			implementation(project(":kapun-util"))
			implementation(project(":kapun-crypto"))
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

skie {
	analytics {
		enabled = false
		disableUpload = true
	}
}

mavenPublishing {
	coordinates(artifactId= property("ARTIFACT_ID").toString(), version= project.version.toString())
	publishToMavenCentral(true)
	signAllPublications()
}
