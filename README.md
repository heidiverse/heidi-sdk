# Heidi SDK 

## Introduction

This repository contains the source code for the Heidi SDK. The SDK is written in Kotlin Multiplatform and can be used to build Android and iOS applications.

## Architecture

The Heidi SDK consists of a collection of independent modules, where each module implements specific features used for digital identity wallets and verifiers.

### Modules

#### Heidi Core
The core module acts as a baseline for the SDK and contains basic functionality used by all other modules. This includes utility and extension functions.

#### Heidi Proximity
The proximity module includes an implementation of the [OpenID for Verifiable Presentations over BLE](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) specification.
This implementation allows a wallet to present verifiable credentials to a verifier over Bluetooth Low Energy (BLE).
Right now, only the transport layer is implemented, the actual credential presentation and verification needs to be done by the implementing wallet and verifier.

#### Sample applications
There are crude sample applications for Android and iOS that demonstrate how to use the Heidi SDK.
Since the SDK is still in early development, they are not yet fully functional and are suspect to change fundamentally.

## Getting started

### Prerequisites
- **JDK 17 or higher**: Ensure that you have a compatible JDK installed.
- **Android Studio**: Required for building and running the Android sample apps.
- **Xcode 15.4 or higher**: Required for building and running the iOS sample app.

### Building the project

#### Android

To build and run the Android sample wallet:

```bash
./gradlew :sample-android-wallet:assembleDebug
./gradlew :sample-android-wallet:installDebug
```

To build and run the Android sample verifier:

```bash
./gradlew :sample-android-verifier:assembleDebug
./gradlew :sample-android-verifier:installDebug
```

#### iOS

To build and run the iOS sample app:

> It is required to open the project folder first in Android Studio to generate the necessary *local.properties* file containing the ANDROID_HOME environment variable.

1. Open `sample-ios-heidi.xcodeproj` in Xcode.
2. The sample project is configured for a specific provisioning profile. To install the app on your own device, you will have to update the settings using your own provisioning profile. You find the signing options in the *sample-ios-heidi* Target configation
3. Select the target device or simulator. Note that the device is required to have iOS 16.0 or higher installed.
4. Click the Run button in Xcode.

#### Running JVM Code (MacOS)
1. Configure `˜/.cargo/config.toml` by setting
 ```bash
      [target.x86_64-unknown-linux-gnu]
      linker = "x86_64-linux-gnu-gcc"
      
      [target.aarch64-unknown-linux-gnu]
      linker = "aarch64-linux-gnu-gcc"
 ```

2. Install macos cross toolchains (https://github.com/messense/homebrew-macos-cross-toolchains)
 ```bash
   brew tap messense/macos-cross-toolchains
   # install x86_64-unknown-linux-gnu toolchain
   brew install x86_64-unknown-linux-gnu
   # install aarch64-unknown-linux-gnu toolchain
   brew install aarch64-unknown-linux-gnu
  ```

3. Set up env var:
 ```bash
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
 ``` 
4. Install minGW64:
 ```bash
  brew install mingw-w64
 ```

## License
This project is licensed under the terms of the Apache License 2. See the [LICENSE](./LICENSE) file for details.
