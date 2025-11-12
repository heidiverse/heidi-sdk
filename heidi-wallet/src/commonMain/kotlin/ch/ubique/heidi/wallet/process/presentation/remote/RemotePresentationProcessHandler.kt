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

package ch.ubique.heidi.wallet.process.presentation.remote

import ch.ubique.heidi.trust.TrustFrameworkController
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.transform
import ch.ubique.heidi.wallet.credentials.ViewModelFactory
import ch.ubique.heidi.wallet.credentials.activity.ActivityRepository
import ch.ubique.heidi.wallet.credentials.credential.CredentialStore
import ch.ubique.heidi.wallet.credentials.credential.CredentialsRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityRepository
import ch.ubique.heidi.wallet.crypto.SigningProvider
import ch.ubique.heidi.wallet.keyvalue.KeyValueRepository
import ch.ubique.heidi.wallet.process.ProcessEvent
import ch.ubique.heidi.wallet.process.ProcessHandler
import ch.ubique.heidi.wallet.process.ProcessStep
import io.ktor.client.HttpClient
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNames
import kotlinx.serialization.json.decodeFromJsonElement
import uniffi.heidi_dcql_rust.DcqlQuery
import uniffi.heidi_util_rust.Value
 
@Serializable
data class DCRequests @OptIn(ExperimentalSerializationApi::class) constructor(@JsonNames("requests", "providers") val providers: List<DCProvider>) {
	@Serializable
	data class DCProvider(val request: String? = null, val data: Value? = null, val protocol : String?) {
		fun getInnerRequest(json: Json) : String? {
			val request = request ?: data ?: return null
			val wrappedRequest: WrappedRequest? = when(request) {
				is String ->  kotlin.runCatching { json.decodeFromString<WrappedRequest>(request)}.getOrNull()
				is Value.String ->  kotlin.runCatching { json.decodeFromString<WrappedRequest>(request.v1)}.getOrNull()
				is Value.Object -> request.transform()
				else -> return null
			}
			wrappedRequest?.let {
				return it.request
			} ?: return when(request) {
				is String ->  request
				is Value -> request.asString()
				else -> return null
			}
		}
	}
	@Serializable
	data class WrappedRequest @OptIn(ExperimentalSerializationApi::class) constructor(@JsonNames("client_id") val clientId: String? = null, val request: String)

}

class RemotePresentationProcessHandler(
    private val client: HttpClient,
    private val signingProvider: SigningProvider,
    private val trustController: TrustFrameworkController,
    private val identityRepository: IdentityRepository,
    private val credentialsRepository: CredentialsRepository,
    private val activityRepository: ActivityRepository,
    private val keyValueRepository: KeyValueRepository,
    private val viewModelFactory: ViewModelFactory,
    private val credentialStore: CredentialStore,
    private val json: Json,
) : ProcessHandler {

	private var currentProcess: RemotePresentationProcess? = null

	override suspend fun handleProcessStep(current: ProcessStep?, inputEvent: ProcessEvent): ProcessStep? {
		return when {
			// A new remote presentation process is started
			inputEvent is RemotePresentationProcessEvent.PresentationRequested -> {
				currentProcess = RemotePresentationProcess(
					client,
					signingProvider,
					trustController,
					identityRepository,
					credentialsRepository,
					activityRepository,
					keyValueRepository,
					viewModelFactory,
					json,
				)
				val data = if(inputEvent.isDCApi) {
					val element : DCRequests? = runCatching { json.decodeFromString<DCRequests>(inputEvent.qrCodeData) }.getOrNull() ?: null
					element?.providers?.firstOrNull()?.getInnerRequest(json) ?: ""
				} else {
					inputEvent.qrCodeData
				}
				currentProcess?.startPresentationProcess(
					data,
					inputEvent.presentationScope,
					inputEvent.authSession,
					inputEvent.isDCApi,
					inputEvent.selectedId,
					inputEvent.origin,
					inputEvent.useLegacyVpToken,
				)
			}

			// Current step is part of the remote presentation process
			current is RemotePresentationProcessStep -> when (current) {
				is RemotePresentationProcessStep.ConnectionDetails -> currentProcess?.continueAfterConnectionTrust()
				is RemotePresentationProcessStep.CredentialSelection -> {
					if (inputEvent is RemotePresentationProcessEvent.CredentialSelected) {
						currentProcess?.continueWithSelectedCredential(inputEvent.credentialMapping)
					} else null
				}
				is RemotePresentationProcessStep.OutOfTokens -> when (inputEvent) {
					is RemotePresentationProcessEvent.RefreshRequested -> currentProcess?.refreshAndReSelect(current.identityIdsToRefresh)
					is RemotePresentationProcessEvent.FallbackRandomRequested -> currentProcess?.continueWithCredentialSelection(allowUsedCredentials = true)
					else -> null
				}
				is RemotePresentationProcessStep.EnterPin -> {
					if (inputEvent is RemotePresentationProcessEvent.PinEntered) {
						currentProcess?.continueWithPinOrPassphrase(
							inputEvent.credentialsWithPin.toMutableList(),
							inputEvent.credentialsWithFrost.toMutableList(),
							inputEvent.viewModel,
							pin = inputEvent.pin,
						)
					} else null
				}
				is RemotePresentationProcessStep.EnterPassphrase -> {
					if (inputEvent is RemotePresentationProcessEvent.PassphraseEntered) {
						currentProcess?.continueWithPinOrPassphrase(
							mutableListOf(),
							inputEvent.credentialsWithFrost.toMutableList(),
							inputEvent.viewModel,
							passphrase = inputEvent.passphrase,
						)
					} else null
				}
				is RemotePresentationProcessStep.Error -> TODO("How to handle event for error step?")
				is RemotePresentationProcessStep.Success, is RemotePresentationProcessStep.DcApiSuccess -> null
			}
			current is RemotePresentationProcessStep.QesProcessStep -> when (current) {
				is RemotePresentationProcessStep.QesProcessStep.Preview -> currentProcess?.continueWithCredentialSelection()
				is RemotePresentationProcessStep.QesProcessStep.CreationAcceptance -> currentProcess?.continueAfterCreationAcceptance()
				is RemotePresentationProcessStep.QesProcessStep.SignDocument -> currentProcess?.finalize()
			}

			else -> null
		}
	}

	override suspend fun cleanupHandler() {
		currentProcess = null
	}
}
