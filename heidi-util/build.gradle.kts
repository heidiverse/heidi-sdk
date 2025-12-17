plugins {
	alias(libs.plugins.kotlin.multiplatform)
	alias(libs.plugins.android.library)
	alias(libs.plugins.skie)
	alias(libs.plugins.vanniktech.publish)
	alias(libs.plugins.kotlin.atomicfu)
	alias(libs.plugins.uniffi.plugin)
	alias(libs.plugins.kotlin.serialization)
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
		
		iosArm64(),
		iosSimulatorArm64()
	).forEach { iosTarget ->
		iosTarget.binaries.framework {
			baseName = "heidi-util"
			isStatic = true
		}

		iosTarget.binaries.all {
			freeCompilerArgs += "-Xallocator=mimalloc"
		}
	}

	sourceSets {
		commonMain.dependencies {
			implementation(libs.kotlin.coroutines)
			implementation(libs.kotlin.datetime)
			implementation(libs.kotlin.serialization)

			implementation(libs.koin.core)
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
	namespace = "ch.ubique.heidi.util"
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
//		variants.forEach {
//			if(it.rustTarget == RustAndroidTarget.Arm64) {
//				debug.profile = CargoProfile.Dev
//			} else {
//				debug.profile = CargoProfile.Release
//			}
//		}
//	}
//	builds.desktop {
//		debug.profile = CargoProfile.Release
//	}
//	builds.appleMobile {
//		debug.profile = CargoProfile.Release
//	}
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