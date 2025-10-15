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

import ch.ubique.heidi.credentials.models.metadata.KeyMaterial
import ch.ubique.heidi.wallet.crypto.factories.BatchSignerFactory
import ch.ubique.heidi.wallet.crypto.factories.NativeSignerFactory
import uniffi.heidi_wallet_rust.*

class SigningProvider(
	private val signerFactories: List<NativeSignerFactory>,
	private val batchSignerFactories: List<BatchSignerFactory>,
	private val secureHardwareAccess: SecureHardwareAccess,
) {

	fun getSecureSubject(
		keyMaterial: KeyMaterial,
		frostBlob: String? = null,
		pin: String? = null,
		passphrase: String? = null,
		email: String? = null,
	): SecureSubject? {
		val nativeSigner = when (keyMaterial) {
			is KeyMaterial.Local -> getNativeSigner(keyMaterial)
			is KeyMaterial.Cloud -> getNativeSigner(keyMaterial, pin = pin)
			is KeyMaterial.Frost -> getNativeSigner(keyMaterial, frostBlob = frostBlob, email = email, passphrase = passphrase)
			is KeyMaterial.Unusable -> getNativeSigner(keyMaterial)
		}

		return nativeSigner?.let { SecureSubject.withSigner(it) }
	}

	fun getNativeSigner(
		keyMaterial: KeyMaterial,
		pin: String? = null,
		frostBlob: String? = null,
		passphrase: String? = null,
		email: String? = null,
	): NativeSigner? {
		return signerFactories.firstNotNullOfOrNull {
			it.createSigner(keyMaterial, pin, frostBlob, passphrase, email)
		}
	}

	fun getBatchSigner(
		keyMaterial: KeyMaterial,
		pin: String? = null,
		frostBlob: String? = null,
		passphrase: String? = null,
		email: String? = null,
	): BatchSigner? {
		return batchSignerFactories.firstNotNullOfOrNull {
			it.createBatchSigner(keyMaterial, pin, frostBlob, passphrase, email)
		}
	}

	fun createSigner(keyType: KeyType): NativeSigner? {
		return when (keyType) {
			KeyType.SOFTWARE -> SoftwareKeyPair().asNativeSigner()
			KeyType.DEVICE_BOUND -> secureHardwareAccess.newHardwareSigner(SecureHardwareAccessControl.BIOMETRY)
			KeyType.REMOTE_HSM -> null
			KeyType.NONE -> null
		}
	}

	fun createHardwareSigner(accessControl: SecureHardwareAccessControl): NativeSigner {
		return secureHardwareAccess.newHardwareSigner(accessControl)
	}

}
