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

import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import ch.ubique.heidi.util.extensions.toData
import ch.ubique.heidi.util.log.Logger
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import platform.CoreBluetooth.*
import platform.Foundation.NSError
import platform.Foundation.NSNumber
import platform.darwin.NSObject
import kotlin.uuid.Uuid

internal class GattClient (
	internal val serviceUuid: Uuid
): BleGattClient {
	internal var listener: BleGattClientListener? = null
	private var isReady: Boolean = false
	internal var centralManagerDelegate : CBCentralManagerDelegateProtocol? = null
	internal val peripheralDelegate = PeripheralDelegate(this)

	private var manager : CBCentralManager? = null

	internal val discoveredPeripherals = mutableListOf<CBPeripheral>()
	internal val peripheralCharacteristics = mutableMapOf<CBPeripheral, List<BleGattCharacteristic>>()
	internal val characteristicDescriptors = mutableMapOf<BleGattCharacteristic, List<CBDescriptor>>()

	internal val incomingMessages: MutableMap<Uuid, okio.Buffer> = mutableMapOf()

	internal var connectedPeripheral: CBPeripheral? = null
	private val pendingWrites = ArrayDeque<PendingWrite>()

	override val characteristicValueSize: Int
		get() = connectedPeripheral?.maximumWriteValueLengthForType(1)?.toInt() ?: 23

	init {
		manager = CBCentralManager(centralManagerDelegate, null)
		centralManagerDelegate = CentralManagerDelegate(this, manager!!) {
			isReady = it
		}
		manager?.setDelegate(centralManagerDelegate)
	}

	override fun setListener(listener: BleGattClientListener?) {
		this.listener = listener
	}

	override fun connect(deviceMacAddress: String) {
		TODO("this is not possible on iOS since mac addresses are not exposed")
	}

	override fun startScanning(listener: BleScannerListener) {
		while(!isReady) {
			runBlocking { delay(300) }
			Logger("GattClient").debug("not ready")
		}
		manager!!.scanForPeripheralsWithServices(listOf(CBUUID.UUIDWithString(serviceUuid.toString())),null)
	}

	override fun stopScanning() {
		manager!!.stopScan()
	}

	override fun supportsSessionTermination(): Boolean {
		return true
	}

	override fun disconnect() {
		connectedPeripheral?.let {
			manager!!.cancelPeripheralConnection(it)
		}

		connectedPeripheral = null
		pendingWrites.clear()
	}

	override fun readCharacteristic(charUuid: Uuid) {
		connectedPeripheral?.let { peripheral ->
			peripheralCharacteristics[peripheral]
				?.find { it.uuid == charUuid }
				?.let { peripheral.readValueForCharacteristic(it.characteristic) }

		}
	}

	override fun writeCharacteristic(charUuid: Uuid, data: ByteArray) {
		Logger("GattClient").debug("write chunked: $charUuid (${data.size})")
		connectedPeripheral?.let { peripheral ->
			peripheralCharacteristics[peripheral]
				?.find { it.uuid == charUuid }
				?.let { char ->
					chunkMessage(data) { chunk ->
						enqueueWrite(char.characteristic, chunk)
					}
				}
		}
	}

	override fun writeCharacteristicNonChunked(charUuid: Uuid, data: ByteArray) {
		Logger("GattClient").debug("write non chunked: $charUuid (${data.size})")
		connectedPeripheral?.let { peripheral ->
			peripheralCharacteristics[peripheral]
				?.find { it.uuid == charUuid }
				?.let {
//					Logger("GattClient").debug("queueing non chunked write")
					enqueueWrite(it.characteristic, data)
				}
		}
	}

	override fun readDescriptor(charUuid: Uuid, descriptorUuid: Uuid) {
		connectedPeripheral?.let { peripheral ->
			peripheralCharacteristics[peripheral]
				?.find { it.uuid == charUuid }
				?.let {
					it.descriptors
						?.map { it as CBDescriptor }
						?.find { descriptor -> descriptor.UUID.UUIDString.lowercase() == descriptorUuid.toString().lowercase() }
						?.let {
							peripheral.readValueForDescriptor(it)
						}

				}
		}
	}

	override fun writeDescriptor(charUuid: Uuid, descriptorUuid: Uuid, data: ByteArray) {
		connectedPeripheral?.let { peripheral ->
			peripheralCharacteristics[peripheral]
				?.find { it.uuid == charUuid }
				?.let {
					it.descriptors
						?.map { it as CBDescriptor }
						?.find { descriptor -> descriptor.UUID.UUIDString.lowercase() == descriptorUuid.toString().lowercase() }
						?.let {
							peripheral.writeValue(data.toData(), it)
						}

				}
		}
	}

	internal fun notifyReadyToSend(peripheral: CBPeripheral) {
		if (peripheral != connectedPeripheral) {
			return
		}
//		Logger("GattClient").debug("peripheralIsReadyToSendWriteWithoutResponse -> flushing ${pendingWrites.size} chunks")
		flushPendingWrites()
	}

	internal fun onPeripheralDisconnected(peripheral: CBPeripheral) {
		if (peripheral != connectedPeripheral) {
			return
		}
//		Logger("GattClient").debug("Peripheral disconnected -> clearing ${pendingWrites.size} queued writes")
		pendingWrites.clear()
		connectedPeripheral = null
		incomingMessages.clear()
	}

	private fun enqueueWrite(characteristic: CBCharacteristic, payload: ByteArray) {
		pendingWrites.addLast(PendingWrite(characteristic, payload))
		flushPendingWrites()
	}

	private fun flushPendingWrites() {
		val peripheral = connectedPeripheral ?: return
		while (pendingWrites.isNotEmpty()) {
			if (!peripheral.canSendWriteWithoutResponse()) {
//				Logger("GattClient").debug("Waiting for peripheral readiness; queued chunks=${pendingWrites.size}")
				return
			}
			val next = pendingWrites.removeFirst()
			peripheral.writeValue(next.payload.toData(), next.characteristic, CBCharacteristicWriteWithoutResponse)
		}
	}

	private data class PendingWrite(
		val characteristic: CBCharacteristic,
		val payload: ByteArray
	)
}
