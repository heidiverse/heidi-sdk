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

import ch.ubique.heidi.proximity.ble.client.toByteArray
import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import ch.ubique.heidi.util.extensions.toData
import ch.ubique.heidi.util.log.Logger
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlin.collections.ArrayDeque
import platform.CoreBluetooth.CBAdvertisementDataServiceUUIDsKey
import platform.CoreBluetooth.CBATTErrorSuccess
import platform.CoreBluetooth.CBATTErrorUnlikelyError
import platform.CoreBluetooth.CBATTRequest
import platform.CoreBluetooth.CBCentral
import platform.CoreBluetooth.CBCharacteristic
import platform.CoreBluetooth.CBMutableCharacteristic
import platform.CoreBluetooth.CBMutableService
import platform.CoreBluetooth.CBPeripheralManager
import platform.CoreBluetooth.CBService
import platform.CoreBluetooth.CBUUID
import platform.Foundation.NSError
import kotlin.uuid.Uuid

internal class GattServer (
    private val serviceUuid: Uuid
): BleGattServer, GattServerDelegate.Handler {
    private var listener: BleGattServerListener? = null
    private var advertiserListener: BleAdvertiserListener? = null
    private var service: CBMutableService? = null
    private var manager: CBPeripheralManager? = null
    private var isReady: Boolean = false
    private var canUpdateSubscribers = true

    private val chunkAccumulator = ChunkAccumulator<String>()
    private val pendingWrites = ArrayDeque<PendingWrite>()

    private val delegate = GattServerDelegate(this)

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
		service = CBMutableService(CBUUID.UUIDWithString(serviceUuid.toString()), true).also {
			it.setCharacteristics(characteristics.map { it.characteristic })
		}
		manager?.addService(service!!)

		service?.characteristics?.forEach {
			val mut = it as? CBMutableCharacteristic
			Logger.debug("Characteristc: ${mut?.UUID?.UUIDString} properties: ${mut?.properties} descriptors: ${mut?.descriptors}")
		}

		return true
	}


	override fun startAdvertising(listener: BleAdvertiserListener) {
		advertiserListener = listener
		manager?.startAdvertising(mapOf(
			CBAdvertisementDataServiceUUIDsKey to listOf(CBUUID.UUIDWithString(serviceUuid.toString()))
		))
	}

    override fun stopAdvertising() {
        manager?.stopAdvertising()
    }

    override fun supportsSessionTermination(): Boolean {
        return true
    }

    override fun stop() {
        manager?.stopAdvertising()
        chunkAccumulator.clear()
        pendingWrites.clear()
    }

	override fun writeCharacteristic(charUuid: Uuid, data: ByteArray) {
		Logger.debug("GattServer: trying to write to: $charUuid, mtu: $characteristicValueSize")
		service?.characteristics?.map { it as CBMutableCharacteristic }?.find { it.UUID == CBUUID.UUIDWithString(charUuid.toString()) }?.let {
			chunkMessage(data) { chunked ->
				pendingWrites.addLast(PendingWrite(it, chunked))
			}
			flushPendingWrites()
		}
	}

    override fun writeCharacteristicNonChunked(charUuid: Uuid, data: ByteArray) {
        service?.characteristics?.map { it as CBMutableCharacteristic }?.find { it.UUID == CBUUID.UUIDWithString(charUuid.toString()) }?.let {
            pendingWrites.addLast(PendingWrite(it, data))
            flushPendingWrites()
        }
    }

    override val characteristicValueSize: Int
        get() = 512

    override fun onStateUpdated(peripheral: CBPeripheralManager) {
        Logger.debug("Peripheral Manager did update state ${peripheral.state} / ${peripheral.isAdvertising()} ")
        isReady = peripheral.state == 5L
        if (!isReady) {
            chunkAccumulator.clear()
            pendingWrites.clear()
            canUpdateSubscribers = false
        } else {
            canUpdateSubscribers = true
            flushPendingWrites()
        }
    }

    override fun onRead(peripheral: CBPeripheralManager, request: CBATTRequest) {
        Logger.debug("Peripheral Manager didReceiveReadRequest")
        val characteristic = request.characteristic ?: return
        listener?.onCharacteristicReadRequest(BleGattCharacteristic(characteristic))
    }

    override fun onWrite(peripheral: CBPeripheralManager, requests: List<*>) {
        Logger.debug("Peripheral Manager didReceiveWriteRequests $requests")

        requests.forEach { anyReq ->
            val request = anyReq as? CBATTRequest ?: return@forEach
            val characteristic = request.characteristic ?: return@forEach
            val uuidString = characteristic.UUID?.UUIDString ?: return@forEach
            val value = request.value?.toByteArray() ?: byteArrayOf()

            if (value.isEmpty()) {
                return@forEach
            }

            when (val chunkResult = chunkAccumulator.consume(uuidString, value)) {
                ChunkProcessingResult.Waiting -> { }
                is ChunkProcessingResult.Complete -> {
                    listener?.onCharacteristicWriteRequest(
                        BleGattCharacteristic(characteristic, chunkResult.payload)
                    )
                }
                is ChunkProcessingResult.Single -> {
                    listener?.onCharacteristicWriteRequest(
                        BleGattCharacteristic(characteristic, chunkResult.payload)
                    )
                }
            }
        }
    }

    override fun onStartAdvertising(peripheral: CBPeripheralManager, error: NSError?) {
        Logger.debug("Peripheral Manager did start advertising error: $error")
    }

    override fun onAddService(peripheral: CBPeripheralManager, service: CBService, error: NSError?) {
        Logger.debug("Peripheral Manager didAddService advertising error: $error")
    }

    override fun onReadyToUpdateSubscribers(peripheral: CBPeripheralManager) {
        Logger.debug("Peripheral Manager peripheralManagerIsReadyToUpdateSubscribers")
        canUpdateSubscribers = true
        flushPendingWrites()
    }

    override fun onSubscribe(
        peripheral: CBPeripheralManager,
        central: CBCentral,
        characteristic: CBCharacteristic
    ) {
        Logger.debug("Peripheral Manager did didSubscribeToCharacteristic: ${characteristic.UUID.UUIDString}")
    }

    private fun flushPendingWrites() {
        val currentManager = manager ?: return
        if (!canUpdateSubscribers && pendingWrites.isNotEmpty()) {
            Logger.debug("GattServer: waiting for peripheralManagerIsReadyToUpdateSubscribers, queued chunks: ${pendingWrites.size}")
            return
        }
        while (pendingWrites.isNotEmpty()) {
            val next = pendingWrites.first()
            Logger.debug("GattServer: sending chunk ${next.payload.size} bytes to characteristic ${next.characteristic}")
            val success = currentManager.updateValue(next.payload.toData(), next.characteristic, null)
            Logger.debug("GattServer: sending returned $success")
            if (success == true) {
                pendingWrites.removeFirst()
            } else {
                canUpdateSubscribers = false
                break
            }
        }
    }

    private data class PendingWrite(
        val characteristic: CBMutableCharacteristic,
        val payload: ByteArray
    )
}
