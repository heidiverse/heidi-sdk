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
package ch.ubique.heidi.proximity.ble.server

import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import ch.ubique.heidi.util.extensions.toData
import ch.ubique.heidi.util.log.Logger
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import platform.CoreBluetooth.CBMutableCharacteristic
import platform.CoreBluetooth.CBMutableService
import platform.CoreBluetooth.CBPeripheralManager
import platform.CoreBluetooth.CBUUID
import kotlin.uuid.Uuid

internal class GattServer (
	private val serviceUuid: Uuid
): BleGattServer {
	private var listener: BleGattServerListener? = null
	private var advertiserListener: BleAdvertiserListener? = null
	private var service: CBMutableService? = null
	private var manager: CBPeripheralManager? = null
	private var isReady: Boolean = false

	private val delegate = GattServerDelegate(listener) {
		isReady = true
	}

	init {
		manager = CBPeripheralManager(delegate, null)
	}

	override fun setListener(listener: BleGattServerListener?) {
		this.listener = listener
	}

	override fun start(characteristics: List<BleGattCharacteristic>): Boolean {
		while(!isReady) {
			runBlocking { delay(300) }
		}
		// TODO BM: why is this crashing, its not if called from swift code
		service = CBMutableService(CBUUID.UUIDWithString(serviceUuid.toString()), true).also {
			it.setCharacteristics(characteristics.map { it.characteristic })
		}
		manager?.addService(service!!)
		return true
	}


	override fun startAdvertising(listener: BleAdvertiserListener) {
		advertiserListener = listener
		manager?.startAdvertising(null)
	}

	override fun stopAdvertising() {
		manager?.stopAdvertising()
	}

	override fun supportsSessionTermination(): Boolean {
		return true
	}

	override fun stop() {
		manager?.stopAdvertising()
	}

	override fun writeCharacteristic(charUuid: Uuid, data: ByteArray) {
		service?.characteristics?.map { it as CBMutableCharacteristic }?.find { it.UUID.UUIDString == charUuid.toString() }?.let {
			chunkMessage(data) { chunked ->
				manager?.updateValue(chunked.toData(), it, null)
			}
		}
	}

	override fun writeCharacteristicNonChunked(charUuid: Uuid, data: ByteArray) {
		service?.characteristics?.map { it as CBMutableCharacteristic }?.find { it.UUID.UUIDString == charUuid.toString() }?.let {
			manager?.updateValue(data.toData(), it, null)
		}
	}

	override val characteristicValueSize: Int
		get() = 512
}
