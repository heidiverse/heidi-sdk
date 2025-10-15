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

package ch.ubique.heidi.issuance.credential.offer

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Credential Offer Parameters as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-credential-offer-parameters
 */
@Serializable
data class CredentialOfferParameters(
	@SerialName("credential_issuer")
	val credentialIssuer: String,

	@SerialName("credential_configuration_ids")
	val credentialConfigurationIds: List<String>,

	@SerialName("grants")
	val grants: Grants? = null,
)

@Serializable
data class Grants(
	@SerialName("authorization_code")
	val authorizationCode: AuthorizationCode? = null,

	@SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code")
	val preAuthorizedCode: PreAuthorizedCode? = null,
)

@Serializable
data class AuthorizationCode(
	@SerialName("issuer_state")
	val issuerState: String? = null,

	@SerialName("authorization_server")
	val authorizationServer: String? = null,
)

@Serializable
data class PreAuthorizedCode(
	@SerialName("pre-authorized_code")
	val preAuthorizedCode: String,

	@SerialName("tx_code")
	val txCode: TransactionCode? = null,

	@SerialName("interval")
	val interval: Int? = null,

	@SerialName("authorization_server")
	val authorizationServer: String? = null,
)

@Serializable
data class TransactionCode(
	@SerialName("input_mode")
	val inputMode: InputMode? = null,

	@SerialName("length")
	val length: Int? = null,

	@SerialName("description")
	val description: String? = null,
)

enum class InputMode {
	@SerialName("numeric")
	NUMERIC,

	@SerialName("text")
	TEXT,
}
