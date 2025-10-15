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

import ch.ubique.heidi.util.log.Logger
import ch.ubique.heidi.wallet.process.ProcessRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.launch
import org.koin.dsl.module

class Vc2PdfController private constructor(
	private val processRepository: ProcessRepository,
	private val scope: CoroutineScope,
) {
	companion object {
		val koinModule = module {
			factory { (scope: CoroutineScope) ->
				Vc2PdfController(
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

	// VC2PDF methods
	fun startVc2PdfConversion(flowId: String = "4") {
		scope.launch(Dispatchers.IO) {
			Logger.debug("Vc2PdfProcessEvent.InitiateCredentialToPdf with flowId: $flowId")
			processRepository.continueProcess(
				Vc2PdfProcessEvent.InitiateCredentialToPdf(flowId)
			)
		}
	}

	fun onPresentationCompleted(redirectUri: String) {
		scope.launch(Dispatchers.IO) {
			Logger.debug("Vc2PdfProcessEvent.PresentationCompleted with URI: $redirectUri")
			processRepository.continueProcess(
				Vc2PdfProcessEvent.PresentationCompleted(redirectUri)
			)
		}
	}

}
