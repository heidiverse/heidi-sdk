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
package ch.ubique.heidi.sample.wallet.feature.proximity

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ch.ubique.heidi.proximity.ProximityProtocol
import ch.ubique.heidi.proximity.wallet.ProximityWallet
import ch.ubique.heidi.proximity.wallet.ProximityWalletState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.koin.core.component.KoinComponent
import org.koin.core.module.dsl.viewModelOf
import org.koin.dsl.module
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
class ProximityViewModel : ViewModel(), KoinComponent {

	companion object {
		val koinModule = module {
			viewModelOf(::ProximityViewModel)
		}
	}

	private lateinit var wallet: ProximityWallet

	private val proximityStateMutable = MutableStateFlow<ProximityWalletState>(ProximityWalletState.Initial)
	val proximityState = proximityStateMutable.asStateFlow()

	override fun onCleared() {
		super.onCleared()
		wallet.disconnect()
	}

	fun startEngagement(qrCodeData: String) {
		viewModelScope.launch {
			val qrCodeUri = Uri.parse(qrCodeData)
			val verifierName = qrCodeUri.getQueryParameter("name")!!
			val publicKey = qrCodeUri.getQueryParameter("key")
			val serviceUuid = Uuid.parse(qrCodeUri.getQueryParameter("uuid")!!)

			wallet = ProximityWallet.create(ProximityProtocol.OPENID4VP, viewModelScope, serviceUuid)
			wallet.startEngagement(verifierName)
			startCollectingWalletState()
		}
	}
	fun startEngagementMdl() {
		viewModelScope.launch {
			val serviceUuid = Uuid.random()
			val peripheralUuid = Uuid.random()
			wallet = ProximityWallet.create(ProximityProtocol.MDL, viewModelScope, serviceUuid, peripheralUuid)
			wallet.startEngagement("")
			startCollectingWalletState()
		}
	}

	fun submitDocument() {
		viewModelScope.launch {
			wallet.submitDocument("success".encodeToByteArray())
		}
	}

	private fun startCollectingWalletState() {
		viewModelScope.launch {
			wallet.walletState.collect { state ->
				proximityStateMutable.value = state
			}
		}
	}

}
