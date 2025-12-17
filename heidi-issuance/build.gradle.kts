import ch.ubique.uniffi.plugin.extensions.useRustUpLinker

plugins {
	alias(libs.plugins.kotlin.multiplatform)
	alias(libs.plugins.kotlin.atomicfu)
	alias(libs.plugins.kotlin.serialization)
	alias(libs.plugins.android.library)
	alias(libs.plugins.skie)
	alias(libs.plugins.uniffi.plugin)
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
		
		iosArm64(),
		iosSimulatorArm64()
	).forEach { iosTarget ->
		iosTarget.binaries.framework {
			baseName = "heidi-issuance"
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
			implementation(project(":heidi-util"))
			implementation(project(":heidi-crypto"))
			implementation(libs.kotlin.coroutines)
			implementation(libs.kotlin.serialization)

			implementation(libs.koin.core)

			implementation(libs.ktor.client.cio)
			implementation(libs.ktor.client.content.negotiation)
			implementation(libs.ktor.serialization.json)
		}

		commonTest.dependencies {
			implementation(libs.kotlin.test)
		}

		androidMain.dependencies {
			implementation(libs.koin.android)
		}

		iosMain.dependencies {
			implementation(libs.ktor.client.darwin)
		}
	}
}

android {
	namespace = "ch.ubique.heidi.issuance"
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
//	builds.android {
//		debug.profile = CargoProfile.Dev
//	}
//	builds.desktop {
//		debug.profile = CargoProfile.Release
//	}
//	builds.appleMobile {
//		debug.profile = CargoProfile.Release
//	}
}

mavenPublishing {
	coordinates(artifactId= property("ARTIFACT_ID").toString(), version= project.version.toString())
	publishToMavenCentral(true)
	signAllPublications()
}