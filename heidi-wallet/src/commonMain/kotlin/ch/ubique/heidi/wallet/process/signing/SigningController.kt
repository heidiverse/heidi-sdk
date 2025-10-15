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

package ch.ubique.heidi.wallet.process.signing

import ch.ubique.heidi.util.log.Logger
import ch.ubique.heidi.wallet.process.ProcessRepository
import ch.ubique.heidi.wallet.process.signing.qes.QesPdfSigningProcessEvent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.launch
import org.koin.dsl.module

class SigningController private constructor(
	private val processRepository: ProcessRepository,
	private val scope: CoroutineScope,
) {
	companion object {
		val koinModule = module {
			factory { (scope: CoroutineScope) ->
				SigningController(
					processRepository = get(),
					scope = scope,
				)
			}
		}
	}

	val currentProcessStep = processRepository.currentProcessStep

	fun resetState() {
		scope.launch(Dispatchers.IO) {
			processRepository.cancelProcess()
		}
	}

	// QES PDF Signing methods
	fun startQesPdfSigning(pdfData: ByteArray, fileName: String) {
		scope.launch(Dispatchers.IO) {
			Logger.debug("QesPdfSigningProcessEvent.InitiatePdfSigning with fileName: $fileName")
			processRepository.continueProcess(
				QesPdfSigningProcessEvent.InitiatePdfSigning(pdfData, fileName)
			)
		}
	}

	fun onQesPresentationCompleted(redirectUri: String) {
		scope.launch(Dispatchers.IO) {
			Logger.debug("QesPdfSigningProcessEvent.PresentationCompleted with URI: $redirectUri")
			processRepository.continueProcess(
				QesPdfSigningProcessEvent.PresentationCompleted(redirectUri)
			)
		}
	}

	fun onQesPdfSigningAccepted() {
		scope.launch(Dispatchers.IO) {
			Logger.debug("QesPdfSigningProcessEvent.UserAcceptedSigning")
			processRepository.continueProcess(
				QesPdfSigningProcessEvent.UserAcceptedSigning
			)
		}
	}

	fun onQesPdfSigningRejected() {
		scope.launch(Dispatchers.IO) {
			Logger.debug("QesPdfSigningProcessEvent.UserRejectedSigning")
			processRepository.continueProcess(
				QesPdfSigningProcessEvent.UserRejectedSigning
			)
		}
	}

}
