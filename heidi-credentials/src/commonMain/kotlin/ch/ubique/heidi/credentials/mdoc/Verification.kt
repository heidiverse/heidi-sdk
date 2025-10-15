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

@file:OptIn(ExperimentalTime::class)

package ch.ubique.heidi.credentials.mdoc

import ch.ubique.heidi.credentials.Mdoc
import ch.ubique.heidi.credentials.mdoc.MDocVerificationException.*
import ch.ubique.heidi.util.extensions.*
import uniffi.heidi_credentials_rust.decodeMdoc
import uniffi.heidi_crypto_rust.*
import uniffi.heidi_util_rust.JsonNumber
import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.decodeCbor
import uniffi.heidi_util_rust.encodeCbor
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

sealed interface VerificationStep {
	data object Validity : VerificationStep
	data object DocType : VerificationStep
	data object IssuerSignature : VerificationStep
	data object CertChain : VerificationStep
	data class DeviceSignature(
		val audience: String,
		val responseUri: String,
		val mdocGeneratedNonce: String,
		val nonce: String,
	) : VerificationStep

	data object IssuerSigned : VerificationStep
}

sealed class MDocVerificationException(message: String) :
	Exception("Failed to verify MDoc: $message") {
	class NotYetValidException(validFrom: String, now: String) :
		MDocVerificationException("Not yet valid: validFrom = $validFrom, now = $now")

	class DocumentExpiredException(validUntil: String, now: String) :
		MDocVerificationException("Document expired: validUntil = $validUntil, now = $now")

	class FailedToVerifyX509ChainException() :
		MDocVerificationException("Failed to verify x509 chain")

	class DocTypeDoesNotMatchException(should: String, actual: String) :
		MDocVerificationException("DocType doesn't match: should = $should, actual = $actual")

	class InvalidIssuerSignatureException() :
		MDocVerificationException("Failed to verify issuer signature")

	class UnsupportedDeviceKeyTypeException(keyType: Long?) :
		MDocVerificationException("Unsupported device key type: $keyType")

	class UnsupportedDeviceKeyAlgException(alg: Long?) :
		MDocVerificationException("Unsupported device key alg: $alg")

	class InvalidDeviceSignatureException() :
		MDocVerificationException("Failed to verify device signature")

	class InvalidDigestException(digestId: String) :
		MDocVerificationException("Invalid digest of item with digestID = $digestId")
}

private fun digest(algorithm: String, value: ByteArray): ByteArray =
	when (algorithm) {
		"SHA-256" -> sha256Rs(value)
		else -> throw Exception("Unknown Digest Algorithm: $algorithm")
	}

fun Mdoc.Companion.parseAndVerify(
	document: Value,
	steps: Set<VerificationStep>,
): Result<Mdoc> {
	val mdoc = Mdoc(decodeMdoc(base64UrlEncode(encodeCbor(document["issuerSigned"]))))
	val mso = mdoc.getMso()

	for (step in steps) {
		when (step) {
			is VerificationStep.Validity -> {
				val validFrom =
					Instant.parse(mso["validityInfo"]["validFrom"].asTag()?.value[0]?.asString()!!)
				val validUntil =
					Instant.parse(mso["validityInfo"]["validUntil"].asTag()?.value[0]?.asString()!!)
				val now = kotlin.time.Clock.System.now()

				if (validFrom > now)
					return Result.failure(
						NotYetValidException(
							validFrom.toString(),
							now.toString()
						)
					)

				if (validUntil < now)
					return Result.failure(
						DocumentExpiredException(
							validUntil.toString(),
							now.toString()
						)
					)
			}

			VerificationStep.CertChain -> {
				val unprotectedHeader = document["issuerSigned"]["issuerAuth"][1]
				val x5Chain =
					unprotectedHeader.asOrderedObject()!![Value.Number(JsonNumber.Integer(33))]!!.asBytes()!!
				val certs = extractCerts(x5Chain)

				if (!verifyChain(certs))
					return Result.failure(FailedToVerifyX509ChainException())
			}

			VerificationStep.DocType -> {
				if (mso["docType"].asString() != mdoc.doctype())
					return Result.failure(
						DocTypeDoesNotMatchException(
							mso["docType"].asString()!!,
							mdoc.doctype()!!
						)
					)
			}

			VerificationStep.IssuerSignature -> {
				if (!mdoc.verify().getOrThrow())
					return Result.failure(InvalidIssuerSignatureException())
			}

			is VerificationStep.DeviceSignature -> {
				val deviceKey = mso["deviceKeyInfo"]["deviceKey"].let {
					val map = it.asOrderedObject()!!
					val kty = map[Value.Number(JsonNumber.Integer(1))]?.asLong()
					val alg = map[Value.Number(JsonNumber.Integer(-1))]?.asLong()

					if (kty != 2L) // EC2
						return Result.failure(UnsupportedDeviceKeyTypeException(kty))
					if (alg != 1L) // P256
						return Result.failure(UnsupportedDeviceKeyAlgException(alg))

					val x = map[Value.Number(JsonNumber.Integer(-2))]?.asBytes()!!
					val y = map[Value.Number(JsonNumber.Integer(-3))]?.asBytes()!!

					VerificationKey.fromCoords(base64UrlEncode(x), base64UrlEncode(y))
				}
				val deviceSigned = document["deviceSigned"]
				val deviceAuth = deviceSigned["deviceAuth"]

				val signature = deviceAuth["deviceSignature"]
				val payload = encodeCbor(
					Value.Tag(
						tag = 24UL, value = listOf(
							Value.Bytes(
								encodeCbor(
									Value.Array(
										listOf(
											Value.String("DeviceAuthentication"),
											Value.Array(
												listOf(
													Value.Null,
													Value.Null,
													Value.Array(
														listOf(
															Value.Bytes(
																digest(
																	"SHA-256", encodeCbor(
																		Value.Array(
																			listOf(
																				Value.String(step.audience),
																				Value.String(step.mdocGeneratedNonce)
																			)
																		)
																	)
																)
															),
															Value.Bytes(
																digest(
																	"SHA-256", encodeCbor(
																		Value.Array(
																			listOf(
																				Value.String(step.responseUri),
																				Value.String(step.mdocGeneratedNonce)
																			)
																		)
																	)
																)
															),
															Value.String(step.nonce)
														)
													)
												)
											),
											Value.String(mdoc.doctype()!!),
											deviceSigned["nameSpaces"]
										)
									)
								)
							)
						)
					)
				)

				val sigStructure = listOf(
					"Signature1",
					signature[0].asBytes(),
					ByteArray(0),
					payload
				).toCbor()

				if (!deviceKey.verify(signature[3].asBytes()!!, encodeCbor(sigStructure)))
					return Result.failure(InvalidDeviceSignatureException())
			}

			is VerificationStep.IssuerSigned -> {
				for ((name, ns) in document["issuerSigned"]["nameSpaces"].asOrderedObject()?.entries!!) {
					val digests = mso["valueDigests"][name.asString()!!].asOrderedObject()!!
					val items = ns.asArray()!!.map { it }

					for (it in items) {
						val item = decodeCbor(it.asTag()?.value[0]?.asBytes()!!)
						val digestId = item["digestID"]
						val digest = digests[digestId]

						if (!digest?.asBytes().contentEquals(
								digest(
									mso["digestAlgorithm"].asString()!!,
									encodeCbor(it)
								)
							)
						)
							return Result.failure(InvalidDigestException(digestId.toString()))
					}
				}
			}
		}
	}

	return Result.success(mdoc)
}
