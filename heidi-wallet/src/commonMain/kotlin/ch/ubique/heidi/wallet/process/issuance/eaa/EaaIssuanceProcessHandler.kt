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

package ch.ubique.heidi.wallet.process.issuance.eaa

import ch.ubique.heidi.util.log.Logger
import ch.ubique.heidi.trust.TrustFrameworkController
import ch.ubique.heidi.wallet.HeidiDatabase
import ch.ubique.heidi.wallet.credentials.ViewModelFactory
import ch.ubique.heidi.wallet.credentials.activity.ActivityRepository
import ch.ubique.heidi.wallet.credentials.credential.CredentialsRepository
import ch.ubique.heidi.wallet.credentials.credential.DeferredCredentialsRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityRepository
import ch.ubique.heidi.wallet.credentials.issuer.IssuerRepository
import ch.ubique.heidi.wallet.credentials.oca.OcaRepository
import ch.ubique.heidi.wallet.credentials.oca.networking.OcaServiceController
import ch.ubique.heidi.wallet.crypto.SecureHardwareAccess
import ch.ubique.heidi.wallet.crypto.SigningProvider
import ch.ubique.heidi.wallet.keyvalue.KeyValueRepository
import ch.ubique.heidi.wallet.process.ProcessEvent
import ch.ubique.heidi.wallet.process.ProcessHandler
import ch.ubique.heidi.wallet.process.ProcessStep
import ch.ubique.heidi.wallet.process.presentation.remote.RemotePresentationProcessStep
import kotlinx.serialization.json.Json
import uniffi.heidi_wallet_rust.OidcSettings

open class EaaIssuanceProcessHandler(
	private val signingProvider: SigningProvider,
	private val trustController: TrustFrameworkController,
	private val issuerRepository: IssuerRepository,
	private val identityRepository: IdentityRepository,
	private val credentialsRepository: CredentialsRepository,
	private val deferredCredentialsRepository: DeferredCredentialsRepository,
	private val activityRepository: ActivityRepository,
	private val keyValueRepository: KeyValueRepository,
	private val ocaRepository: OcaRepository,
	private val ocaServiceController: OcaServiceController,
	private val viewModelFactory: ViewModelFactory,
	private val json: Json,
	private val secureHardwareAccess: SecureHardwareAccess,
	private val oidcSettings: OidcSettings,
	private val db: HeidiDatabase,
) : ProcessHandler {

	private var currentProcess: EaaIssuanceProcess? = null

	override suspend fun handleProcessStep(current: ProcessStep?, inputEvent: ProcessEvent): ProcessStep? {
		return when {
			// A new EAA issuance process is started
			inputEvent is EaaIssuanceProcessEvent.CredentialOfferReceived -> {
				currentProcess = EaaIssuanceProcess(
					signingProvider = signingProvider,
					issuerRepository = issuerRepository,
					identityRepository = identityRepository,
					activityRepository = activityRepository,
					keyValueRepository = keyValueRepository,
					viewModelFactory = viewModelFactory,
					secureHardwareAccess = secureHardwareAccess,
					json = json,
					trustController = trustController,
					credentialsRepository = credentialsRepository,
					deferredCredentialsRepository = deferredCredentialsRepository,
					ocaRepository = ocaRepository,
					ocaServiceController = ocaServiceController,
					db = db
				)
				currentProcess?.startIssuance(inputEvent.credentialOfferString)
			}
			inputEvent is EaaIssuanceProcessEvent.DeferredIssuance -> {
				currentProcess = EaaIssuanceProcess(
					signingProvider = signingProvider,
					issuerRepository = issuerRepository,
					identityRepository = identityRepository,
					activityRepository = activityRepository,
					keyValueRepository = keyValueRepository,
					viewModelFactory = viewModelFactory,
					json = json,
					trustController = trustController,
					credentialsRepository = credentialsRepository,
					deferredCredentialsRepository = deferredCredentialsRepository,
					ocaRepository = ocaRepository,
					ocaServiceController = ocaServiceController,
					secureHardwareAccess = secureHardwareAccess,
					db = db
				)
				currentProcess?.startDeferred(inputEvent.transactionId)
			}

			// Current step is part of the EAA issuance process
			current is EaaIssuanceProcessStep -> {
					if (currentProcess == null) {
						Logger.error("currentProcess has to be initialized before handling EAA issuance process steps")
					}
					when (current) {
						is EaaIssuanceProcessStep.ConnectionDetails -> currentProcess?.loadCredentialPreview(oidcSettings)
						is EaaIssuanceProcessStep.CredentialOfferPreview -> currentProcess?.continueWithEaaIssuance()
						is EaaIssuanceProcessStep.TransactionCode -> {
							if (inputEvent is EaaIssuanceProcessEvent.TransactionCodeEntered) {
								currentProcess?.finalizeEaaIssuance(transactionCode = inputEvent.transactionCode)
							} else null
						}
						is EaaIssuanceProcessStep.PushedAuthorization -> {
							if (inputEvent is EaaIssuanceProcessEvent.AuthorizationCodeReceived) {
								currentProcess?.finalizeEaaIssuance(authorizationCode = inputEvent.authorizationCode)
							} else null
						}
						is EaaIssuanceProcessStep.Presentation -> {
							if (inputEvent is EaaIssuanceProcessEvent.PresentationSuccessful) {
								currentProcess?.continueAfterPresentation(
									inputEvent.authSession,
									inputEvent.scope,
									inputEvent.pdiSession
								)
							} else null
						}
						is EaaIssuanceProcessStep.CredentialOffer -> currentProcess?.acceptCredentialOffer()
						is EaaIssuanceProcessStep.Error -> null
						is EaaIssuanceProcessStep.Success -> null
					}
			}

			// A presentation during issuance was successful
			current is RemotePresentationProcessStep.Success -> {
				if (inputEvent is EaaIssuanceProcessEvent.PresentationSuccessful) {
					currentProcess?.continueAfterPresentation(
						authSession = inputEvent.authSession,
						scope = inputEvent.scope,
						pdiSession = inputEvent.pdiSession,
					)
				} else null
			}

			else -> null
		}
	}

	override suspend fun cleanupHandler() {
		currentProcess = null
	}

}
