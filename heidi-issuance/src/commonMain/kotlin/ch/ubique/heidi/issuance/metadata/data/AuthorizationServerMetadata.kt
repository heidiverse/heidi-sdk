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

/**
 * Authorization Server Metadata as described here: https://datatracker.ietf.org/doc/html/rfc8414#section-2
 */
@Serializable
data class AuthorizationServerMetadata(

	@SerialName("issuer")
	val issuer: String,

	@SerialName("authorization_endpoint")
	val authorizationEndpoint: String?,

	@SerialName("token_endpoint")
	val tokenEndpoint: String?,

	@SerialName("jwks_uri")
	val jwksUri: String?,

	@SerialName("registration_endpoint")
	val registrationEndpoint: String?,

	@SerialName("scopes_supported")
	val scopesSupported: List<String>?,

	@SerialName("response_types_supported")
	// An Authorization Server that only supports the Pre-Authorized Code grant type MAY omit the response_types_supported parameter in its metadata despite [RFC8414] mandating it.
	val responseTypesSupported: List<String>?,

	@SerialName("response_modes_supported")
	val responseModesSupported: List<String>?,

	@SerialName("grant_types_supported")
	val grantTypesSupported: List<String>?,

	@SerialName("token_endpoint_auth_methods_supported")
	val tokenEndpointAuthMethodsSupported: List<String>?,

	@SerialName("token_endpoint_auth_signing_alg_values_supported")
	val tokenEndpointAuthSigningAlgValuesSupported: List<String>?,

	@SerialName("service_documentation")
	val serviceDocumentation: String?,

	@SerialName("ui_locales_supported")
	val uiLocalesSupported: List<String>?,

	@SerialName("op_policy_uri")
	val opPolicyUri: String?,

	@SerialName("op_tos_uri")
	val opTosUri: String?,

	@SerialName("revocation_endpoint")
	val revocationEndpoint: String?,

	@SerialName("revocation_endpoint_auth_methods_supported")
	val revocationEndpointAuthMethodsSupported: List<String>?,

	@SerialName("revocation_endpoint_auth_signing_alg_values_supported")
	val revocationEndpointAuthSigningAlgValuesSupported: List<String>?,

	@SerialName("introspectionEndpoint")
	val introspectionEndpoint: String?,

	@SerialName("introspectionEndpointAuthMethodsSupported")
	val introspectionEndpointAuthMethodsSupported: List<String>?,

	@SerialName("introspectionEndpointAuthSigningAlgValuesSupported")
	val introspectionEndpointAuthSigningAlgValuesSupported: List<String>?,

	@SerialName("codeChallengeMethodsSupported")
	val codeChallengeMethodsSupported: List<String>?,

	/**
	 * Additional field as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-oauth-authorization-server-
	 */
	@SerialName("pre-authorized_grant_anonymous_access_supported")
	val preAuthorizedGrandAnonymousAccessSupported: Boolean?,

	/**
	 * Additional field as described in https://datatracker.ietf.org/doc/html/rfc9126#name-authorization-server-metada
	 */
	@SerialName("pushed_authorization_request_endpoint")
	val pushedAuthorizationRequestEndpoint: String?,

	/**
	 * Additional field as described in https://datatracker.ietf.org/doc/html/rfc9126#name-authorization-server-metada
	 */
	@SerialName("require_pushed_authorization_requests")
	val requirePushedAuthorizationRequests: Boolean?,

	/**
	 * Additional field as described in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-11#name-authorization-server-metada
	 */
	@SerialName("dpop_signing_alg_values_supported")
	val dpopSigningAlgValuesSupported: List<String>?,

	/**
	 * Additional field as described in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-first-party-apps#name-authorization-server-metada
	 */
	@SerialName("authorization_challenge_endpoint")
	val authorizationChallengeEndpoint: String?,

	/**
	 * Additional custom field by Ubique. Used to indicate if a credential offer auth type requires presentation first
	 */
	@SerialName("first_party_usage")
	val firstPartyUsage: Boolean?,
)
