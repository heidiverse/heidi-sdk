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
package ch.ubique.heidi.proximity.ble.client

import ch.ubique.heidi.proximity.ProximityError
import ch.ubique.heidi.util.log.Logger
import kotlinx.cinterop.ObjCSignatureOverride
import platform.CoreBluetooth.CBCentralManager
import platform.CoreBluetooth.CBCentralManagerDelegateProtocol
import platform.CoreBluetooth.CBCentralManagerStatePoweredOn
import platform.CoreBluetooth.CBPeripheral
import platform.CoreBluetooth.CBUUID
import platform.Foundation.NSError
import platform.Foundation.NSNumber
import platform.darwin.NSObject

internal class CentralManagerDelegate(
	private val gattClient: GattClient,
	private val manager: CBCentralManager,
	private val isReady: (Boolean) -> Unit
) : NSObject(), CBCentralManagerDelegateProtocol {

	override fun centralManager(
		central: CBCentralManager,
		didDiscoverPeripheral: CBPeripheral,
		advertisementData: Map<Any?, *>,
		RSSI: NSNumber
	) {
		Logger.debug("Central Manager didDiscoverPeripheral")
		gattClient.discoveredPeripherals.add(didDiscoverPeripheral)
		didDiscoverPeripheral.delegate = gattClient.peripheralDelegate
		gattClient.onConnectionAttemptStarted()
		manager.connectPeripheral(didDiscoverPeripheral, null)
	}

	override fun centralManager(central: CBCentralManager, didConnectPeripheral: CBPeripheral) {
		Logger.debug("Connected to peripheral: ${didConnectPeripheral.identifier}")
		didConnectPeripheral.discoverServices(listOf(CBUUID.UUIDWithString(gattClient.serviceUuid.toString())))
		gattClient.connectedPeripheral = didConnectPeripheral
		gattClient.listener?.onPeerConnecting()
	}

	@ObjCSignatureOverride
	override fun centralManager(
		central: CBCentralManager,
		didFailToConnectPeripheral: CBPeripheral,
		error: NSError?
	) {
		gattClient.reportConnectionError(
			ProximityError.ConnectionFailed
		)
	}

	@ObjCSignatureOverride
	override fun centralManager(
		central: CBCentralManager,
		didDisconnectPeripheral: CBPeripheral,
		error: NSError?
	) {
		Logger.debug("Disconnected from peripheral: ${didDisconnectPeripheral.identifier}")
		if (error != null) {
			gattClient.reportConnectionError(
				ProximityError.PeripheralDisconnected
			)
		}
		gattClient.onPeripheralDisconnected(didDisconnectPeripheral)
	}

	override fun centralManagerDidUpdateState(central: CBCentralManager) {
		Logger.debug("Central Manager did update state ${central.state} ${central.isScanning}")
		isReady(central.state == CBCentralManagerStatePoweredOn)
		gattClient.onCentralStateChanged(central.state)
	}
}
