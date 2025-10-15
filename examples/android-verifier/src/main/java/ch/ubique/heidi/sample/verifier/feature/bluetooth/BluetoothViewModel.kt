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
@file:OptIn(ExperimentalUuidApi::class)

package ch.ubique.heidi.sample.verifier.feature.bluetooth

import androidx.lifecycle.ViewModel
import ch.ubique.heidi.proximity.protocol.TransportProtocol
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.koin.core.component.KoinComponent
import org.koin.core.module.dsl.viewModelOf
import org.koin.dsl.module
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

class BluetoothViewModel : ViewModel(), KoinComponent {

	companion object {
		val koinModule = module {
			viewModelOf(::BluetoothViewModel)
		}

		private val SERVICE_UUID = Uuid.parse("19278c0d-7e57-4371-87f7-5315f7db9a86")
	}

	private var transportProtocol: TransportProtocol? = null

	private val transportProtocolListener = object : TransportProtocol.Listener {
		override fun onConnecting() {
			bluetoothStateMutable.value = BluetoothState.Connecting
		}

		override fun onConnected() {
			bluetoothStateMutable.value = BluetoothState.Connected
		}

		override fun onDisconnected() {
			bluetoothStateMutable.value = BluetoothState.Disconnected
		}

		override fun onMessageReceived() {
			val message = transportProtocol?.getMessage()?.decodeToString()
			if (message != null) {
				bluetoothLogMutable.update { it.plus(message) }
			}
		}

		override fun onTransportSpecificSessionTermination() {
			transportProtocol?.disconnect()
		}

		override fun onError(error: Throwable) {
			bluetoothLogMutable.update { it.plus(error.stackTraceToString()) }
		}
	}

	private val bluetoothStateMutable = MutableStateFlow<BluetoothState>(BluetoothState.Idle)
	val bluetoothState = bluetoothStateMutable.asStateFlow()

	private val bluetoothLogMutable = MutableStateFlow<List<String>>(emptyList())
	val bluetoothLog = bluetoothLogMutable.asStateFlow()

	fun startServerMode(role: TransportProtocol.Role) {
		bluetoothLogMutable.value = emptyList()

//		transportProtocol = MdlPeripheralServerModeTransportProtocol(role, SERVICE_UUID, characteristics).also {
//			it.setListener(transportProtocolListener)
//			it.connect()
//			bluetoothStateMutable.update {
//				when (role) {
//					TransportProtocol.Role.WALLET -> BluetoothState.Advertising(SERVICE_UUID)
//					TransportProtocol.Role.VERIFIER -> BluetoothState.Scanning(SERVICE_UUID)
//				}
//			}
//		}
	}

	fun startClientMode(role: TransportProtocol.Role) {
		bluetoothLogMutable.value = emptyList()

//		transportProtocol = MdlCentralClientModeTransportProtocol(role, SERVICE_UUID, characteristics).also {
//			it.setListener(transportProtocolListener)
//			it.connect()
//			bluetoothStateMutable.update {
//				when (role) {
//					TransportProtocol.Role.WALLET -> BluetoothState.Scanning(SERVICE_UUID)
//					TransportProtocol.Role.VERIFIER -> BluetoothState.Advertising(SERVICE_UUID)
//				}
//			}
//		}
	}

	fun sendMessage(message: String) {
		transportProtocol?.sendMessage(message.encodeToByteArray())
	}

	fun stop() {
		transportProtocol?.disconnect()
		transportProtocol = null
		bluetoothStateMutable.value = BluetoothState.Idle
	}

}
