/* Copyright 2025 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

package ch.ubique.heidi.wallet.crypto

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import java.util.Date
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.Uuid

internal object KeyRepository {
	private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeystore").apply { load(null) }
	private const val KEY_LEN = 256 //bits

	fun generateES256KeyPair(): KeyPair {
		// Create a KeyPairGenerator instance for EC (Elliptic Curve)
		val keyPairGenerator = KeyPairGenerator.getInstance("EC")

		// Initialize the KeyPairGenerator with the P-256 curve
		val ecGenParameterSpec = ECGenParameterSpec("secp256r1")
		keyPairGenerator.initialize(ecGenParameterSpec)

		// Generate the KeyPair
		return keyPairGenerator.generateKeyPair()
	}


	fun getKeyPair(alias: String): KeyPair? {
		return (keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry)?.let {
			KeyPair(it.certificate.publicKey, it.privateKey)
		}
	}

	@OptIn(ExperimentalEncodingApi::class)
	fun getKeyAttestation(alias: String): String? {
		val certs = keyStore.getCertificateChain(alias)
		return certs.joinToString(separator = "") {
			"-----BEGIN CERTIFICATE-----\n" + Base64.encode(it.encoded) + "\n-----END CERTIFICATE-----\n";
		}
	}

	fun createKeyPair(context: Context, accessControl: SecureHardwareAccessControl): KeyPairBundle {
		val alias = Uuid.random().toString()
		val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
			KeyProperties.KEY_ALGORITHM_EC,
			"AndroidKeyStore"
		)
		val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
			alias,
			KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
		).run {
			setDigests(KeyProperties.DIGEST_SHA256)
			setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
			if (accessControl == SecureHardwareAccessControl.BIOMETRY) {
				setUserAuthenticationRequired(true)

				// Allow the key to be used for 15min after authentication
				val keyStoreUsageTimeoutInSeconds = 15.minutes.inWholeSeconds.toInt()
				if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
					setUserAuthenticationParameters(keyStoreUsageTimeoutInSeconds, KeyProperties.AUTH_BIOMETRIC_STRONG)
				} else {
					setUserAuthenticationValidityDurationSeconds(keyStoreUsageTimeoutInSeconds)
				}
			}
			val now = Date()
			setAttestationChallenge(now.toString().toByteArray())

			val hasStrongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
			setIsStrongBoxBacked(hasStrongBox)
			build()
		}

		kpg.initialize(parameterSpec)

		return KeyPairBundle(kpg.generateKeyPair(), alias)
	}
}
