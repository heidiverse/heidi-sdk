/* Copyright 2024 Ubique Innovation AG

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
package ch.ubique.heidi.sample.wallet.feature.scanner

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ch.ubique.heidi.sample.wallet.R
import ch.ubique.heidi.sample.wallet.extensions.throttleIf
import ch.ubique.qrscanner.state.DecodingState
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.koin.core.module.dsl.viewModelOf
import org.koin.dsl.module

class QrScannerViewModel : ViewModel() {
	companion object {
		private val supportedSchemes = setOf(
			"openid-credential-offer",
			"openid4vp",
		)

		val koinModule = module {
			viewModelOf(::QrScannerViewModel)
		}
	}

	private val isLightOnMutable = MutableStateFlow(false)
	val isLightOn = isLightOnMutable.asStateFlow()

	private val errorMutable = MutableSharedFlow<Int?>()

	// throttleIf prevents flickering and ensures that the error is shown for at least 1 second
	val error = errorMutable.throttleIf(1000) { it == null }

	private var isScanning = true

	fun switchLightState() {
		isLightOnMutable.value = !isLightOn.value
	}

	fun startScanning() {
		isScanning = true
	}

	fun evaluateScannerResult(decodingState: DecodingState): DecodingResult {
		if (!isScanning) return DecodingResult.Nothing

		viewModelScope.launch { errorMutable.emit(null) }
		return when (decodingState) {
			is DecodingState.Decoded -> {
				val uri = Uri.parse(decodingState.content)
				if (uri.scheme in supportedSchemes) {
					isScanning = false
					DecodingResult.Valid(decodingState.content)
				} else {
					val errorId = R.string.app_name
					viewModelScope.launch { errorMutable.emit(errorId) }
					DecodingResult.Nothing
				}
			}
			else -> DecodingResult.Nothing
		}
	}
}

sealed interface DecodingResult {
	data object Nothing : DecodingResult
	data class Valid(val content: String) : DecodingResult
}
