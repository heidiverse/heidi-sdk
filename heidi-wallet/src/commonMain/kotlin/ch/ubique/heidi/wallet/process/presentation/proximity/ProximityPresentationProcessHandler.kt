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

package ch.ubique.heidi.wallet.process.presentation.proximity

import ch.ubique.heidi.trust.TrustFrameworkController
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
import kotlinx.coroutines.CoroutineScope
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNames


class ProximityPresentationProcessHandler(

	private val signingProvider: SigningProvider,
	private val trustController: TrustFrameworkController,
	private val identityRepository: IdentityRepository,
	private val credentialsRepository: CredentialsRepository,
	private val activityRepository: ActivityRepository,
	private val keyValueRepository: KeyValueRepository,
	private val viewModelFactory: ViewModelFactory,
	private val json: Json,
) : ProcessHandler {

	private var currentProcess: ProximityPresentationProcess? = null

	override suspend fun handleProcessStep(current: ProcessStep?, inputEvent: ProcessEvent): ProcessStep? {
		return when {
			// A new remote presentation process is started
			inputEvent is ProximityPresentationProcessEvent.PresentationRequested -> {
				currentProcess = ProximityPresentationProcess(
					signingProvider,
					trustController,
					identityRepository,
					credentialsRepository,
					activityRepository,
					keyValueRepository,
					viewModelFactory,
					json,
				)
				currentProcess?.startPresentationProcess(inputEvent.engagementData)
			}
			inputEvent is ProximityPresentationProcessEvent.PeerConnecting -> ProximityPresentationProcessStep.PeerConnecting
			inputEvent is ProximityPresentationProcessEvent.PeerConected -> ProximityPresentationProcessStep.PeerConnected
			inputEvent is ProximityPresentationProcessEvent.DocumentRequested -> {
				currentProcess?.continueWithCredentialSelection(inputEvent.documentRequest, inputEvent.sessionTranscript)
			}
			// Current step is part of the remote presentation process
			current is ProximityPresentationProcessStep -> when (current) {
				is ProximityPresentationProcessStep.CredentialSelection -> {
					if (inputEvent is ProximityPresentationProcessEvent.CredentialSelected) {
						currentProcess?.continueWithSelectedCredential(inputEvent.credentialMapping)
					} else null
				}
				is ProximityPresentationProcessStep.EnterPin -> {
					if (inputEvent is ProximityPresentationProcessEvent.PinEntered) {
						currentProcess?.continueWithPinOrPassphrase(
							inputEvent.credentialsWithPin.toMutableList(),
							inputEvent.credentialsWithFrost.toMutableList(),
							inputEvent.viewModel,
							pin = inputEvent.pin,
						)
					} else null
				}
				is ProximityPresentationProcessStep.EnterPassphrase -> {
					if (inputEvent is ProximityPresentationProcessEvent.PassphraseEntered) {
						currentProcess?.continueWithPinOrPassphrase(
							mutableListOf(),
							inputEvent.credentialsWithFrost.toMutableList(),
							inputEvent.viewModel,
							passphrase = inputEvent.passphrase,
						)
					} else null
				}
				is ProximityPresentationProcessStep.Error -> TODO("How to handle event for error step?")
				is ProximityPresentationProcessStep.Success -> null
				else -> null
			}

			else -> null
		}
	}

	override suspend fun cleanupHandler() {
		currentProcess = null
	}
}
