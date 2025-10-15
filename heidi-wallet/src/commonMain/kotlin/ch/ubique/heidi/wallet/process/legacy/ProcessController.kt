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

package ch.ubique.heidi.wallet.process.legacy

import kotlinx.coroutines.CoroutineScope
import org.koin.dsl.module

class ProcessController private constructor(
	private val scope: CoroutineScope,
) {
	companion object {
		val koinModule = module {
			factory { (scope: CoroutineScope) ->
				ProcessController(scope)
			}
		}
	}

	fun determineProcessType(data: String): ProcessType {
		return when {
			data.startsWith("openid-credential-offer") -> {
				// TODO We probably need the get_credential_issuer_metadata functionality from Rust to determine the type of credential being offered, so maybe it makes sense to move this entire functionality into the Rust code?
				// TODO Rust has a resolve_credential_offer function, but it can't be exported for bindings because CredentialOffer is a library type
				if (data.contains("demo.pid-issuer.bundesdruckerei.de")) {
					ProcessType.EID_ISSUANCE
				} else {
					ProcessType.EAA_ISSUANCE
				}
			}
			data.contains("openid4vp") -> {
				if (data.startsWith("openid4vp://connect")) {
					ProcessType.PROXIMITY
				} else {
					ProcessType.PRESENTATION
				}
			}
			data.contains("swiyu") -> {
				if (data.startsWith("swiyu://?credential_offer")) {
					ProcessType.EAA_ISSUANCE
				} else {
					ProcessType.PRESENTATION
				}
			}
			data.startsWith("haip") -> {
				// TODO: is there a better way to determine the flow? (haip:// is used for both flows)
				if (data.contains("presentation_definition") || data.contains("request_uri")) {
					ProcessType.PRESENTATION
				} else {
					ProcessType.EAA_ISSUANCE
				}
			}
			data.startsWith("https") -> {
				// TODO: is there a better way to determine the flow?
				if (data.contains("presentation_definition") || data.contains("request_uri")) {
					ProcessType.PRESENTATION
				} else {
					ProcessType.EAA_ISSUANCE
				}
			}
			else -> ProcessType.UNKNOWN
		}
	}
}
