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

package ch.ubique.heidi.wallet.process.refresh.eaa

import ch.ubique.heidi.trust.TrustFrameworkController
import ch.ubique.heidi.wallet.credentials.activity.ActivityRepository
import ch.ubique.heidi.wallet.credentials.credential.CredentialsRepository
import ch.ubique.heidi.wallet.credentials.identity.IdentityRepository
import ch.ubique.heidi.wallet.credentials.oca.OcaRepository
import ch.ubique.heidi.wallet.credentials.oca.networking.OcaServiceController
import ch.ubique.heidi.wallet.crypto.SecureHardwareAccess
import ch.ubique.heidi.wallet.crypto.SigningProvider
import ch.ubique.heidi.wallet.keyvalue.KeyValueRepository
import ch.ubique.heidi.wallet.process.ProcessEvent
import ch.ubique.heidi.wallet.process.ProcessHandler
import ch.ubique.heidi.wallet.process.ProcessStep

class EaaRefreshProcessHandler(
	private val trustController: TrustFrameworkController,
	private val credentialsRepository: CredentialsRepository,
	private val identityRepository: IdentityRepository,
	private val secureHardwareAccess: SecureHardwareAccess,
	private val signingProvider: SigningProvider,
	private val ocaRepository: OcaRepository,
	private val ocaServiceController: OcaServiceController,
	private val activityRepository: ActivityRepository,
	private val keyValueRepository: KeyValueRepository
): ProcessHandler {

	private var currentProcess: EaaRefreshProcess? = null

	override suspend fun handleProcessStep(
		current: ProcessStep?,
		inputEvent: ProcessEvent,
	): ProcessStep? {
		return when {
			inputEvent is EaaRefreshProcessEvent.RefreshRequests -> {
				currentProcess = EaaRefreshProcess(
					trustController,
					credentialsRepository,
					identityRepository,
					secureHardwareAccess,
					signingProvider,
					ocaRepository,
					ocaServiceController,
					activityRepository,
					keyValueRepository,
				)
				currentProcess?.startEaaRefresh(inputEvent.identity)
			}
			else -> null
		}
	}

	override suspend fun cleanupHandler() {
		currentProcess = null
	}
}
