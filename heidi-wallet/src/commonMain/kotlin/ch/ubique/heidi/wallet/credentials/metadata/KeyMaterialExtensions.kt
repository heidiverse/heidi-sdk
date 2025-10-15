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

package ch.ubique.heidi.wallet.credentials.metadata

import ch.ubique.heidi.credentials.models.metadata.KeyAssurance
import ch.ubique.heidi.credentials.models.metadata.KeyMaterial
import ch.ubique.heidi.wallet.crypto.SecureHardwareAccess
import ch.ubique.heidi.wallet.extensions.toFrostBackup
import uniffi.heidi_wallet_rust.SoftwareKeyPair

inline fun KeyMaterial.toKeyAssurance() : KeyAssurance {
	return when(this) {
		is KeyMaterial.Frost -> KeyAssurance.EmergencyHigh
		is KeyMaterial.Local.HardwareBacked -> KeyAssurance.HardwareMedium
		is KeyMaterial.Local.SoftwareBacked -> KeyAssurance.SoftwareLow
		is KeyMaterial.Cloud -> KeyAssurance.CloudHigh
		is KeyMaterial.Unusable -> KeyAssurance.CloudHigh
		is KeyMaterial.Local.ClaimBased -> KeyAssurance.SoftwareLow
	}
}

inline fun KeyMaterial.isImportable(secureHardwareAccess: SecureHardwareAccess) : Boolean {
	return when (this) {
		is KeyMaterial.Local.HardwareBacked -> {
			val signer = secureHardwareAccess.getHardwareSigner(this.deviceKeyReference)
			return signer != null
		}
		is KeyMaterial.Local.SoftwareBacked -> true
		is KeyMaterial.Cloud -> {
			val signer = secureHardwareAccess.getHardwareSigner(this.deviceKeyReference)
			return signer != null
		}
		is KeyMaterial.Frost -> true
		is KeyMaterial.Unusable -> false
		is KeyMaterial.Local.ClaimBased -> true
	}
}

inline fun KeyMaterial.getPublicKey(frostBlob: String? = null) : ByteArray? {
	return when (this) {
		is KeyMaterial.Local.HardwareBacked -> publicKey
		is KeyMaterial.Frost -> frostBlob?.toFrostBackup()?.pubKeyPackage
		is KeyMaterial.Local.SoftwareBacked -> SoftwareKeyPair.fromPrivateKey(this.privateKey).asNativeSigner().publicKey()
		is KeyMaterial.Cloud -> this.hsmReference.batchPublicKey ?: this.hsmReference.publicKey
		is KeyMaterial.Unusable -> null
		is KeyMaterial.Local.ClaimBased -> null
	}
}
