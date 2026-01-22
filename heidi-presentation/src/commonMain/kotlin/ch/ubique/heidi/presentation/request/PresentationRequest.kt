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

package ch.ubique.heidi.presentation.request

import ch.ubique.heidi.presentation.model.OID4VPVersion
import ch.ubique.heidi.util.extensions.*
import ch.ubique.heidi.wallet.process.presentation.models.TransactionDataWrapper
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonNames
import uniffi.heidi_dcql_rust.DcqlQuery
import uniffi.heidi_util_rust.Value

/**
 * Data class to hold both the OID4VP draft version and the parsed PresentationRequest
 */
data class VersionedPresentationRequest(
	val version: OID4VPVersion,
	val request: PresentationRequest,
)

@Serializable
data class PresentationRequest @OptIn(ExperimentalSerializationApi::class) constructor(
	@SerialName("client_id")
	val clientId: String,
	@EncodeDefault
	@SerialName("response_type")
	val responseType: String = "vp_token",
	@SerialName("client_id_scheme")
	val clientIdScheme: String? = null,
	@SerialName("presentation_definition")
	val presentationDefinition: Value? = null,
	@SerialName("presentation_definition_uri")
	val presentationDefinitionUri: Value? = null,
	@SerialName("dcql_query")
	val dcqlQuery: DcqlQuery? = null,
	@SerialName("transaction_data")
	val transactionData: TransactionDataWrapper? = null,
	@SerialName("client_metadata")
	val clientMetadata: ClientMetadata? = null,
	@SerialName("verifier_attestations")
	val verifierAttestations: List<Value>? = null,
	@SerialName("verifier_info")
	val verifierInfo: List<Value>? = null,
	@SerialName("expected_origins")
	val expectedOrigins: List<String>? = null,
) {
	@Serializable
	data class ClientMetadata(
		@JsonNames("logo_uri") val logoUri: String? = null,
		@JsonNames("client_name") val clientName: String? = null,
	)

	companion object {
		/**
		 * For backward compatibility, calls detectVersionAndParse and returns just the PresentationRequest
		 */
		fun fromValue(value: Value): PresentationRequest? {
			return detectProtocolVersionAndParse(value)?.request
		}

		/**
		 * Detects the OID4VP version from the Value object and returns both the version and the parsed PresentationRequest
		 */
		fun detectProtocolVersionAndParse(value: Value): VersionedPresentationRequest? {
			// Detect version in priority order: 21, 26, 24
			val clientIdScheme = value["client_id_scheme"].takeIf { it != Value.Null }?.asString()

			// Version 21 detection: presence of clientIdScheme
			val version = if (clientIdScheme != null) {
				OID4VPVersion.DRAFT_21
			} else {

				// Version 1.0 detection: presence of verifier_info
				// Version 28 detection: presence of expected_origins in value and presence of vp_formats_supported field in client_metadata
				// Version 26 detection: absence of purpose element in credential_sets and/or presence of multiple field
				val dcqlQueryValue = value["dcql_query"].takeIf { it != Value.Null }

				if (dcqlQueryValue != null) {
					// Check for absence of purpose in credential_sets
					val credentialSets = dcqlQueryValue["credential_sets"].takeIf { it != Value.Null }
					val hasPurposeInCredentialSets = if (credentialSets != null && credentialSets.isArray()) {
						credentialSets.asArray()?.any {
							it["purpose"].takeIf { purpose -> purpose != Value.Null } != null
						} ?: false
					} else {
						false
					}

					// Check for presence of multiple field in credentials
					val credentials = dcqlQueryValue["credentials"].takeIf { it != Value.Null }
					val hasMultipleInCredentials = if (credentials != null && credentials.isArray()) {
						credentials.asArray()?.any {
							it["multiple"].takeIf { multiple -> multiple != Value.Null } != null
						} ?: false
					} else {
						false
					}

					val hasExpectedOrigins = value["expected_origins"].takeIf { it != Value.Null }?.isArray() == true
					val hasVpFormatsSupported =
						value["client_metadata"]["vp_formats_supported"].takeIf { it != Value.Null }?.isObject() == true

					val hasVerifierInfo = value["verifier_info"].takeIf { it != Value.Null }?.isArray() == true

					if (hasVerifierInfo) {
						OID4VPVersion.VERSION_ONE_DOT_ZERO
					} else if (hasExpectedOrigins || hasVpFormatsSupported) {
						OID4VPVersion.DRAFT_28
					} else if (!hasPurposeInCredentialSets || hasMultipleInCredentials) {
						OID4VPVersion.DRAFT_26
					} else {
						// Version 24 is the fallback
						OID4VPVersion.DRAFT_24
					}
				} else {
					// If no dcqlQuery is present, default to version 24
					OID4VPVersion.DRAFT_24
				}
			}
			// Parse the client_id based on the draft version
			val rawClientId = value["client_id"].asString() ?: "dc_api"
			val clientId = rawClientId

			val presentationDefinition = value["presentation_definition"]
			val dcqlQuery: DcqlQuery? = value["dcql_query"]
				.takeIf { it != Value.Null }?.let {
					it.asString()?.let {
						try {
							json.decodeFromString(it)
						} catch (ex: Exception) {
							null
						}
					} ?: it.transform<DcqlQuery>()
				}

			val responseType = value["response_type"].takeIf { it != Value.Null }?.asString() ?: "vp_token"

			val request = PresentationRequest(
				clientId,
				responseType = responseType,
				clientIdScheme = clientIdScheme,
				presentationDefinition = if (presentationDefinition is Value.Null) {
					null
				} else {
					presentationDefinition
				},
				dcqlQuery = dcqlQuery,
				transactionData = TransactionDataWrapper.fromValue(value),
				clientMetadata = value["client_metadata"].transform(),
				verifierAttestations = value["verifier_attestations"].transform(),
				expectedOrigins = value["expected_origins"].transform()
			)

			return VersionedPresentationRequest(version, request)
		}
	}
}
