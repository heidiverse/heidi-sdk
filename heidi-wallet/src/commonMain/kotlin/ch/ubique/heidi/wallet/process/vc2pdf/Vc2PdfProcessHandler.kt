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

package ch.ubique.heidi.wallet.process.vc2pdf

import ch.ubique.heidi.wallet.process.ProcessEvent
import ch.ubique.heidi.wallet.process.ProcessHandler
import ch.ubique.heidi.wallet.process.ProcessStep
import io.ktor.client.HttpClient

class Vc2PdfProcessHandler(
	private val client: HttpClient,
	private val baseUrl: String
) : ProcessHandler {

	private var currentProcess: Vc2PdfProcess? = null

	override suspend fun handleProcessStep(current: ProcessStep?, inputEvent: ProcessEvent): ProcessStep? {
		return when {
			// New VC to PDF conversion process is initiated
			inputEvent is Vc2PdfProcessEvent.InitiateCredentialToPdf -> {
				currentProcess = Vc2PdfProcess(
					client,
					baseUrl,
				)
				currentProcess?.initiateCredentialToPdf(inputEvent.flowId)
			}

			// Handle presentation completion with redirect URI
			inputEvent is Vc2PdfProcessEvent.PresentationCompleted -> {
				currentProcess?.handlePresentationCompleted(inputEvent.redirectUri)
			}

			else -> null
		}
	}

	override suspend fun cleanupHandler() {
		currentProcess = null
	}

}
