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

package ch.ubique.heidi.issuance.metadata

import ch.ubique.heidi.issuance.credential.offer.CredentialOfferParameters
import ch.ubique.heidi.issuance.di.HeidiIssuanceKoinComponent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import org.koin.core.component.inject

class MetadataRepository: HeidiIssuanceKoinComponent {

	private val metadataService by inject<MetadataService>()

	// TODO UBMW: Keep a cache of the metadata

	suspend fun getAuthorizationServerMetadata(baseUrl: String) = withContext(Dispatchers.IO) {
		metadataService.doAuthorizationServerMetadataRequest(baseUrl)
	}

	suspend fun getCredentialIssuerMetadata(baseUrl: String) = withContext(Dispatchers.IO) {
		metadataService.doCredentialIssuerMetadataRequest(baseUrl)
	}

	fun getAuthorizationServerBaseUrl(
		authorizationServers: List<String>,
		credentialOfferParameters: CredentialOfferParameters,
	): String? {
		val expectedAuthServer = credentialOfferParameters.grants?.let {
			it.preAuthorizedCode?.authorizationServer ?: it.authorizationCode?.authorizationServer
		}

		return when {
			expectedAuthServer != null -> {
				// If a specific auth server is expected, return it if it is in the list
				expectedAuthServer.takeIf { authorizationServers.contains(it) }
			}
			authorizationServers.isNotEmpty() -> {
				// Fallback to the first authorization server
				authorizationServers.first()
			}
			else -> {
				// Fallback to the credential issuer
				credentialOfferParameters.credentialIssuer
			}
		}
	}

}
