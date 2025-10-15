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
package ch.ubique.heidi.proximity.ble

import android.bluetooth.BluetoothManager
import android.content.Context
import ch.ubique.heidi.proximity.ble.client.BleGattClient
import ch.ubique.heidi.proximity.ble.client.GattClient
import ch.ubique.heidi.proximity.ble.server.BleGattServer
import ch.ubique.heidi.proximity.ble.server.GattServer
import kotlin.uuid.Uuid
import kotlin.uuid.toJavaUuid

internal actual class BleGattFactory(private val context: Context) {
	internal actual fun isBleAdvSupported() : Boolean {
		val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
		return bm.adapter.isLePeriodicAdvertisingSupported
	}
	internal actual fun createServer(
		serviceUuid: Uuid,
	): BleGattServer {
		val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
		return GattServer(
			context = context,
			bluetoothManager = bm,
			serviceUuid = serviceUuid.toJavaUuid(),
			encodedEphemeralDeviceKey = null, // TODO CBOR encoded ephemeral device public key
		)
	}

	internal actual fun createClient(
		serviceUuid: Uuid,
	): BleGattClient {
		val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
		return GattClient(
			context = context,
			bluetoothManager = bm,
			serviceUuid = serviceUuid.toJavaUuid(),
			encodedEphemeralDeviceKey = null, // TODO CBOR encoded ephemeral device public key
		)
	}

}
