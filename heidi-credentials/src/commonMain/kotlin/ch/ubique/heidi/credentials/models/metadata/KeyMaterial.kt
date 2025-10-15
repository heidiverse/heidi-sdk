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

package ch.ubique.heidi.credentials.models.metadata

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed interface KeyMaterial {

	val storage: KeyStorage
	val type: KeyMaterialType

	@Serializable
	sealed interface Local : KeyMaterial {
		@Serializable
		@SerialName("KeyMaterial.Local.HardwareBacked")
		data class HardwareBacked(
			val deviceKeyReference: ByteArray,
			val publicKey: ByteArray,
		) : Local {
			override val storage = KeyStorage.Local
			@SerialName("keyMaterialType") override val type = KeyMaterialType.LOCAL
		}

		@Serializable
		@SerialName("KeyMaterial.Local.SoftwareBacked")
		data class SoftwareBacked(val privateKey: ByteArray): Local {
			override val storage = KeyStorage.Local
			@SerialName("keyMaterialType") override val type = KeyMaterialType.LOCAL
		}
		@Serializable
		@SerialName("KeyMaterial.Local.ClaimBased")
		class ClaimBased() : Local {
			override val storage: KeyStorage
				get() = KeyStorage.Local
			@SerialName("keyMaterialType") override val type = KeyMaterialType.LOCAL
		}
	}

	@Serializable
	@SerialName("KeyMaterial.Cloud")
	data class Cloud(
		val aesKey: AesReference,
		val deviceKeyReference: ByteArray,
		val hsmReference: HsmReference,
	) : KeyMaterial {
		override val storage = KeyStorage.Cloud
		@SerialName("keyMaterialType") override val type = KeyMaterialType.CLOUD

		@Serializable
		data class AesReference(val key: ByteArray, val nonce: ByteArray)

		@Serializable
		data class HsmReference(
			val walletAttestation: String? = null,
			val uuid: String,
			val publicKey: ByteArray,
			val batchPublicKey: ByteArray? = null,
			val batchKeyId: String? = null,
		)
	}

	@Serializable
	@SerialName("KeyMaterial.Frost")
	data class Frost(val hsmReference: HsmReference) : KeyMaterial {
		override val storage = KeyStorage.Cloud
		@SerialName("keyMaterialType") override val type = KeyMaterialType.FROST

		@Serializable
		data class HsmReference(val walletAttestation: String? = null, val uuid: String, val publicKey: ByteArray)
	}

	/**
	 * This key material is unusable, e.g. because it was imported from a backup but its key material could not be restored
	 */
	@Serializable
	@SerialName("KeyMaterial.Unsuable")
	data object Unusable : KeyMaterial {
		override val storage = KeyStorage.Local
		@SerialName("keyMaterialType") override val type = KeyMaterialType.UNUSABLE
	}

}
