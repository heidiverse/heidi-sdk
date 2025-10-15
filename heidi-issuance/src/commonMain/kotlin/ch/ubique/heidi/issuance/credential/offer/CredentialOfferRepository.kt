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

import ch.ubique.heidi.issuance.di.HeidiIssuanceKoinComponent
import io.ktor.http.Url
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import org.koin.core.component.inject

class CredentialOfferRepository : HeidiIssuanceKoinComponent {

	companion object {
		private const val CREDENTIAL_OFFER_SCHEME = "openid-credential-offer"
		private const val BIT_CREDENTIAL_OFFER_SCHEME = "swiyu"

		private const val PARAM_CREDENTIAL_OFFER_URI = "credential_offer_uri"
		private const val PARAM_CREDENTIAL_OFFER = "credential_offer"
	}

	private val credentialOfferService by inject<CredentialOfferService>()
	private val json by inject<Json>()

	/**
	 * Parses a credential offer from a string according to https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-credential-offer
	 */
	suspend fun parseCredentialOffer(offerString: String): CredentialOfferParameters? = withContext(Dispatchers.IO) {
		// Check if the offer string has the correct scheme
		val parsedOfferString = Url(offerString)
		val protocolName = parsedOfferString.protocol.name
		if (!(protocolName == CREDENTIAL_OFFER_SCHEME || protocolName == BIT_CREDENTIAL_OFFER_SCHEME))  {
			return@withContext null
		}

		// Check if the offer references a URI or contains the parameters directly
		val offerUri = parsedOfferString.parameters[PARAM_CREDENTIAL_OFFER_URI]
		if (offerUri != null) {
			return@withContext credentialOfferService.doCredentialOfferRequest(offerUri)
		} else {
			val offer = parsedOfferString.parameters[PARAM_CREDENTIAL_OFFER]
			return@withContext offer?.let {
				runCatching {
					json.decodeFromString<CredentialOfferParameters>(it)
				}.getOrNull()
			}
		}
	}

}
