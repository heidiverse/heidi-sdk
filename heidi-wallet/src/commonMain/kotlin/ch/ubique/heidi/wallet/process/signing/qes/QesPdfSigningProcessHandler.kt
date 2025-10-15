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

package ch.ubique.heidi.wallet.process.signing.qes

import ch.ubique.heidi.wallet.credentials.signeddocument.SignedDocumentsRepository
import ch.ubique.heidi.wallet.process.ProcessEvent
import ch.ubique.heidi.wallet.process.ProcessHandler
import ch.ubique.heidi.wallet.process.ProcessStep
import io.ktor.client.HttpClient
import kotlinx.serialization.json.Json

class QesPdfSigningProcessHandler(
	private val client: HttpClient,
	private val signedDocumentsRepository: SignedDocumentsRepository,
	private val json: Json,
	private val baseUrl: String,
) : ProcessHandler {

	private var currentProcess: QesPdfSigningProcess? = null

	override suspend fun handleProcessStep(current: ProcessStep?, inputEvent: ProcessEvent): ProcessStep? {
		return when {
			// New QES PDF signing process is initiated
			inputEvent is QesPdfSigningProcessEvent.InitiatePdfSigning -> {
				currentProcess = QesPdfSigningProcess(
					client,
					signedDocumentsRepository,
					json,
					baseUrl,
				)
				currentProcess?.initiatePdfSigning(inputEvent.pdfData, inputEvent.fileName)
			}

			// Handle presentation completion with redirect URI
			inputEvent is QesPdfSigningProcessEvent.PresentationCompleted -> {
				currentProcess?.handlePresentationCompleted(inputEvent.redirectUri)
			}

			else -> null
		}
	}

	override suspend fun cleanupHandler() {
		currentProcess = null
	}

}
