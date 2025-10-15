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

package ch.ubique.heidi.issuance.metadata.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * Credential Issuer Metadata as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
 */
@Serializable
data class CredentialIssuerMetadata(
	@SerialName("credential_issuer")
	val credentialIssuer: String,

	@SerialName("authorization_servers")
	val authorizationServers: List<String>? = null,

	@SerialName("credential_endpoint")
	val credentialEndpoint: String,

	@SerialName("nonce_endpoint")
	val nonceEndpoint: String? = null,

	@SerialName("deferred_credential_endpoint")
	val deferredCredentialEndpoint: String? = null,

	@SerialName("notification_endpoint")
	val notificationEndpoint: String? = null,

	@SerialName("credential_response_encryption")
	val credentialResponseEncryption: CredentialResponseEncryption? = null,

	@SerialName("batch_credential_issuance")
	val batchCredentialIssuance: BatchCredentialIssuance? = null,

	@SerialName("signed_metadata")
	val signedMetadata: String? = null,

	@SerialName("display")
	val display: List<Display>? = null,

	@SerialName("credential_configurations_supported")
	val credentialConfigurationsSupported: Map<String, CredentialConfiguration>,

	@SerialName("vct")
	val vct: String? = null,

	@SerialName("credential_metadata")
	val credentialMetadata: CredentialMetadata? = null,
)

@Serializable
data class CredentialMetadata(
	@SerialName("display")
	val display: List<Display>,

	@SerialName("claims")
	val claims: List<CredentialMetadataClaim>? = null,
)

@Serializable
data class CredentialMetadataClaim(
	@SerialName("path")
	val path: List<String>,

	@SerialName("display")
	val display: List<Display>? = null,

	@SerialName("mandatory")
	val isMandatory: Boolean? = null,
)

@Serializable
data class CredentialResponseEncryption(
	@SerialName("alg_values_supported")
	val algValuesSupported: List<String>,

	@SerialName("enc_values_supported")
	val encValuesSupported: List<String>,

	@SerialName("encryption_required")
	val encryptionRequired: Boolean
)

@Serializable
data class BatchCredentialIssuance(
	@SerialName("batch_size")
	val batchSize: Int,
)

@Serializable
data class Display(
	@SerialName("name")
	val name: String? = null,

	@SerialName("locale")
	val locale: String? = null,

	@SerialName("logo")
	val logo: Logo? = null,

	@SerialName("description")
	val description: String? = null,

	@SerialName("background_color")
	val backgroundColor: String? = null,

	@SerialName("background_image")
	val backgroundImage: BackgroundImage? = null,

	@SerialName("text_color")
	val textColor: String? = null,
)

@Serializable
data class Logo(
	@SerialName("uri")
	// Is required, but we don't need it, so don't fail if metadata is wrong
	val uri: String? = null,

	@SerialName("alt_text")
	val altText: String? = null,
)

@Serializable
data class BackgroundImage(
	@SerialName("uri")
	val uri: String,
)

@Serializable(with = CredentialConfigurationSerializer::class)
sealed interface CredentialConfiguration {
	val format: String
	val scope: String?
	val cryptographicBindingMethodsSupported: List<String>?
	val credentialSigningAlgValuesSupported: List<String>?
	val proofTypesSupported: Map<String, ProofType>?
	val display: List<Display>?

	/**
	 * ISO mDL credential format as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-iso-mdl
	 */
	@Serializable
	data class Mdoc(
		@SerialName("format")
		override val format: String,

		@SerialName("scope")
		override val scope: String? = null,

		@SerialName("cryptographic_binding_methods_supported")
		override val cryptographicBindingMethodsSupported: List<String>? = null,

		@SerialName("credential_signing_alg_values_supported")
		override val credentialSigningAlgValuesSupported: List<String>? = null,

		@SerialName("proof_types_supported")
		override val proofTypesSupported: Map<String, ProofType>? = null,

		@SerialName("display")
		override val display: List<Display>? = null,

		@SerialName("doctype")
		val doctype: String,

		@SerialName("claims")
		val claims: JsonElement? = null,
	) : CredentialConfiguration

	/**
	 * SD-JWT VC credential format as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-ietf-sd-jwt-vc
	 */
	@Serializable
	data class SdJwt(
		@SerialName("format")
		override val format: String,

		@SerialName("scope")
		override val scope: String? = null,

		@SerialName("cryptographic_binding_methods_supported")
		override val cryptographicBindingMethodsSupported: List<String>? = null,

		@SerialName("credential_signing_alg_values_supported")
		override val credentialSigningAlgValuesSupported: List<String>? = null,

		@SerialName("proof_types_supported")
		override val proofTypesSupported: Map<String, ProofType>? = null,

		@SerialName("display")
		override val display: List<Display>? = null,

		@SerialName("vct")
		val vct: String,

		@SerialName("claims")
		val claims: JsonElement? = null,
	) : CredentialConfiguration

	@Serializable
	data class SdJwtVcdm(
		@SerialName("format")
		override val format: String,

		@SerialName("scope")
		override val scope: String? = null,

		@SerialName("cryptographic_binding_methods_supported")
		override val cryptographicBindingMethodsSupported: List<String>? = null,

		@SerialName("credential_signing_alg_values_supported")
		override val credentialSigningAlgValuesSupported: List<String>? = null,

		@SerialName("proof_types_supported")
		override val proofTypesSupported: Map<String, ProofType>? = null,

		@SerialName("display")
		override val display: List<Display>? = null,

		@SerialName("claims")
		val claims: JsonElement? = null,

		@SerialName("credential_definition")
		val credentialDefinition: VcdmCredentialDefinition? = null
	) : CredentialConfiguration

	/**
	 * Fallback for unknown credential formats
	 */
	@Serializable
	data class Unknown(
		@SerialName("format")
		override val format: String,

		@SerialName("scope")
		override val scope: String? = null,

		@SerialName("cryptographic_binding_methods_supported")
		override val cryptographicBindingMethodsSupported: List<String>? = null,

		@SerialName("credential_signing_alg_values_supported")
		override val credentialSigningAlgValuesSupported: List<String>? = null,

		@SerialName("proof_types_supported")
		override val proofTypesSupported: Map<String, ProofType>? = null,

		@SerialName("display")
		override val display: List<Display>? = null,
	) : CredentialConfiguration

}

@Serializable
data class ProofType(
	@SerialName("proof_signing_alg_values_supported")
	val proofSigningAlgValuesSupported: List<String>,

	@SerialName("key_attestations_required")
	val keyAttestationsRequired: KeyAttestationsRequired? = null,
)

@Serializable
data class KeyAttestationsRequired(
	@SerialName("key_storage")
	val keyStorage: List<String>? = null,

	@SerialName("user_authentication")
	val userAuthentication: List<String>? = null,
)

@Serializable
data class VcdmCredentialDefinition(
	@SerialName("type")
	val type: List<String>? = null
)
