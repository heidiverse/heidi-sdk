/* Copyright 2024 Ubique Innovation AG

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
package ch.ubique.heidi.proximity.util

import ch.ubique.heidi.proximity.protocol.mdl.DcApiCapability
import ch.ubique.heidi.proximity.protocol.mdl.MdlCapabilities
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_crypto_rust.SessionCipher
import uniffi.heidi_crypto_rust.sha256Rs
import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.encodeCbor

object ProximityMdlUtils {
	enum class PayloadDecryptFailureType {
		SHA_MISMATCH,
		MISSING_CIPHER,
		DECRYPT_FAILED,
	}

	sealed class PayloadDecryptResult {
		data class Success(val data: ByteArray) : PayloadDecryptResult()
		data class Failure(
			val type: PayloadDecryptFailureType,
			val debugMessage: String,
		) : PayloadDecryptResult()
	}

	fun defaultDcApiCapabilities(): MdlCapabilities {
		return MdlCapabilities(
			mapOf(
				MdlCapabilities.DC_API_CAPABILITY_KEY to DcApiCapability(
					listOf("openid4vp-v1-unsigned", "openid4vp-v1-signed")
				)
			)
		)
	}

	fun buildIsoOriginFromSessionTranscript(sessionTranscript: Value): String {
		val sessionTranscriptBytes = encodeCbor(sessionTranscript)
		val sessionTranscriptBytesHash = base64UrlEncode(sha256Rs(sessionTranscriptBytes))
		return "iso-18013-5://${sessionTranscriptBytesHash}"
	}

	fun decryptAndValidatePayload(
		encryptedPayload: ByteArray,
		expectedSha: ByteArray?,
		sessionCipher: SessionCipher?,
	): PayloadDecryptResult {
		expectedSha?.let { expected ->
			val actualSha = sha256Rs(encryptedPayload)
			if (!expected.contentEquals(actualSha)) {
				return PayloadDecryptResult.Failure(
					PayloadDecryptFailureType.SHA_MISMATCH,
					"sha mismatch expected=${base64UrlEncode(expected)} actual=${base64UrlEncode(actualSha)}",
				)
			}
		}

		val currentCipher = sessionCipher ?: return PayloadDecryptResult.Failure(
			PayloadDecryptFailureType.MISSING_CIPHER,
			"missing session cipher",
		)

		val data = currentCipher.decrypt(encryptedPayload) ?: return PayloadDecryptResult.Failure(
			PayloadDecryptFailureType.DECRYPT_FAILED,
			"failed to decrypt payload of size ${encryptedPayload.size}",
		)

		return PayloadDecryptResult.Success(data)
	}
}
