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

package ch.ubique.heidi.wallet.process

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

class ProcessRepository(
	private val processHandlers: List<ProcessHandler>,
) {

	private val currentProcessStepMutable = MutableStateFlow<ProcessStep?>(null)
	val currentProcessStep = currentProcessStepMutable.asStateFlow()

	suspend fun continueProcess(inputEvent: ProcessEvent = ProcessEvent.Continue) {
		val currentStep = currentProcessStep.value

		if (currentStep is ProcessStep.ProcessCompleted) {
			// No further action should be taken if the process is already completed
			cleanupProcesses()
			currentProcessStepMutable.update { null }
		}

		// Transform the current step to a loading step
		currentProcessStepMutable.update { currentStep?.toLoading(inputEvent) ?: ProcessStep.Loading }

		// Go through all process handlers until one of them can handle the current step and input event
		val nextStep = processHandlers.firstNotNullOfOrNull {
			it.handleProcessStep(currentStep, inputEvent)
		}

		return if (nextStep == null) {
			// If no handler could handle the current step and input event, consider the process completed
			cleanupProcesses()
			currentProcessStepMutable.update { ProcessStep.ProcessCompleted }
		} else {
			// In all other cases update the step and wait for the next input event
			currentProcessStepMutable.update { nextStep }
		}
	}

	suspend fun cancelProcess() {
		cleanupProcesses()
		currentProcessStepMutable.update { null }
	}

	private suspend fun cleanupProcesses() {
		processHandlers.forEach { it.cleanupHandler() }
	}

}
