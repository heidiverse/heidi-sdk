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

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import ch.ubique.heidi.proximity.ble.gatt.BleGattCharacteristic
import ch.ubique.heidi.proximity.protocol.BleTransportProtocol
import ch.ubique.heidi.proximity.protocol.TransportProtocol
import ch.ubique.heidi.util.log.Logger
import java.util.ArrayDeque
import java.util.Arrays
import java.util.Queue
import java.util.UUID
import kotlin.uuid.Uuid
import kotlin.uuid.toJavaUuid

@SuppressLint("MissingPermission")
internal class GattServer(
	private val context: Context,
	private val bluetoothManager: BluetoothManager,
	private val serviceUuid: UUID,
	private val encodedEphemeralDeviceKey: ByteArray?, // TODO Use for session encryption
) : BluetoothGattServerCallback(), BleGattServer {

	companion object {
		private const val TAG = "GattServer"

		private val SHUTDOWN_UUID = Uuid.random()
	}

	private var listener: BleGattServerListener? = null
	private var inhibitCallbacks = false

	private var characteristics: List<BleGattCharacteristic> = emptyList()

	private var gattServer: BluetoothGattServer? = null
	private var currentConnection: BluetoothDevice? = null
	private var negotiatedMtu = 0

    private val chunkAccumulator = ChunkAccumulator<UUID>()
	private val readQueues = mutableMapOf<UUID, Queue<ByteArray>>().withDefault { ArrayDeque() }
	private val writingQueues = mutableMapOf<UUID, Queue<ByteArray>>().withDefault { ArrayDeque() }

	private var characteristicValueSizeMemoized = 0
	override val characteristicValueSize: Int
		get() {
			if (characteristicValueSizeMemoized > 0) {
				return characteristicValueSizeMemoized
			}
			var mtuSize = negotiatedMtu
			if (mtuSize == 0) {
				Logger(TAG).warn("MTU not negotiated, defaulting to 23. Performance will suffer.")
				mtuSize = 23
			}
			characteristicValueSizeMemoized = BleTransportProtocol.bleCalculateAttributeValueSize(mtuSize)
			return characteristicValueSizeMemoized
		}

	private var advertiser: BluetoothLeAdvertiser? = null
	private var advertiserListener: BleAdvertiserListener? = null
	private val advertiserCallback = object : AdvertiseCallback() {
		override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {}

		override fun onStartFailure(errorCode: Int) {
			advertiserListener?.onError("BLE advertise failed with error code $errorCode")
		}
	}

	override fun setListener(listener: BleGattServerListener?) {
		this.listener = listener
	}

	override fun start(characteristics: List<BleGattCharacteristic>): Boolean {
		this.characteristics = characteristics
		gattServer = try {
			bluetoothManager.openGattServer(context, this)
		} catch (e: Exception) {
			reportError(e)
			return false
		}

		// This happens for example if Bluetooth is turned off
		if (gattServer == null) return false

		val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY)

		characteristics.forEach { characteristic ->
			service.addCharacteristic(characteristic.characteristic)
		}

		try {
			requireServer().addService(service)
		} catch (e: SecurityException) {
			reportError(e)
			return false
		}
		return true
	}

	override fun startAdvertising(listener: BleAdvertiserListener) {
		advertiserListener = listener

		val settings = AdvertiseSettings.Builder()
			.setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
			.setConnectable(true)
			.setTimeout(0)
			.setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
			.build()
		val data = AdvertiseData.Builder()
			.setIncludeTxPowerLevel(false)
			.addServiceUuid(ParcelUuid(serviceUuid))
			.build()

		try {
			advertiser = bluetoothManager.adapter.bluetoothLeAdvertiser.also {
				it.startAdvertising(settings, data, advertiserCallback)
			}
		} catch (e: Exception) {
			advertiserListener?.onError(e.message ?: e.javaClass.simpleName)
		}
	}

	override fun stopAdvertising() {
		try {
			advertiser?.stopAdvertising(advertiserCallback)
		} catch (e: Exception) {
			advertiserListener?.onError(e.message ?: e.javaClass.simpleName)
		} finally {
			advertiser = null
		}
	}

	override fun supportsSessionTermination(): Boolean {
		return true
	}

	override fun stop() {
		inhibitCallbacks = true
		if (gattServer != null) {
			// used to convey we want to shutdown once all write are done.
			writeCharacteristicNonChunked(SHUTDOWN_UUID, TransportProtocol.SHUTDOWN_MESSAGE)
		}
	}

	override fun writeCharacteristic(charUuid: Uuid, data: ByteArray) {
		// Only initiate the write if no other write was outstanding for the same characteristic
		val queueNeedsDraining = writingQueues.getValue(charUuid.toJavaUuid()).size == 0


		chunkMessage(data) { chunk ->
			writingQueues.getOrPut(charUuid.toJavaUuid()) { ArrayDeque() }.add(chunk)
		}

		if (queueNeedsDraining) {
			drainWritingQueue(charUuid.toJavaUuid())
		}
	}

	override fun writeCharacteristicNonChunked(charUuid: Uuid, data: ByteArray) {
		// Only initiate the write if no other write was outstanding for the same characteristic
		val queueNeedsDraining = writingQueues.getValue(charUuid.toJavaUuid()).size == 0


		writingQueues.getOrPut(charUuid.toJavaUuid()) { ArrayDeque() }.add(data)

		if (queueNeedsDraining) {
			drainWritingQueue(charUuid.toJavaUuid())
		}
	}

	override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
		// We assume that we only have one connection at a time
		when (newState) {
            BluetoothProfile.STATE_CONNECTED -> {
                currentConnection = device
                chunkAccumulator.clear()
                requireServer().connect(currentConnection, false)
                reportPeerConnected()
            }
            BluetoothProfile.STATE_DISCONNECTED -> {
                currentConnection = null
                chunkAccumulator.clear()
                reportPeerDisconnected()
            }
        }
    }

	override fun onCharacteristicReadRequest(
		device: BluetoothDevice,
		requestId: Int,
		offset: Int,
		characteristic: BluetoothGattCharacteristic,
	) {
		// Ignore requests from devices other than the one we are currently connected with
		if (currentConnection?.address != device.address) {
			sendResponse(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED)
			return
		}

		// If there is already a read queued, send back the next chunk. Otherwise notify the listener and chunk its response
		val charUuid = characteristic.uuid
		val success = if (readQueues.getValue(charUuid).isEmpty()) {
			val result = requireListener().onCharacteristicReadRequest(BleGattCharacteristic(characteristic))
			if (result.data != null && result.data.isNotEmpty()) {
				chunkMessage(result.data) { chunk ->
					readQueues.getOrPut(charUuid) { ArrayDeque() }.add(chunk)
				}
			}
			result.isSuccessful
		} else true

		val chunkData = readQueues.getValue(charUuid).poll() ?: null

		sendResponse(
			device,
			requestId,
			if (success) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE,
			0,
			chunkData
		)
	}

	override fun onCharacteristicWriteRequest(
		device: BluetoothDevice,
		requestId: Int,
		characteristic: BluetoothGattCharacteristic,
		preparedWrite: Boolean,
		responseNeeded: Boolean,
		offset: Int,
		value: ByteArray,
	) {
		// Ignore requests from devices other than the one we are currently connected with
		if (currentConnection?.address != device.address) {
			sendResponse(device, requestId, BluetoothGatt.GATT_WRITE_NOT_PERMITTED)
			return
		}

        val charUuid = characteristic.uuid
        val result = when (val chunkResult = chunkAccumulator.consume(charUuid, value)) {
            is ChunkProcessingResult.Complete -> {
                requireListener().onCharacteristicWriteRequest(
                    BleGattCharacteristic(characteristic, chunkResult.payload)
                )
            }
            ChunkProcessingResult.Waiting -> GattRequestResult(isSuccessful = true)
            is ChunkProcessingResult.Single -> {
                requireListener().onCharacteristicWriteRequest(
                    BleGattCharacteristic(characteristic, chunkResult.payload)
                )
            }
        }

        if (responseNeeded) {
            sendResponse(
				device,
				requestId,
				if (result.isSuccessful) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE,
				0,
				result.data
			)
		}
	}

	override fun onDescriptorReadRequest(
		device: BluetoothDevice,
		requestId: Int,
		offset: Int,
		descriptor: BluetoothGattDescriptor,
	) {
		// Ignore requests from devices other than the one we are currently connected with
		if (currentConnection?.address != device.address) {
			sendResponse(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED)
			return
		}

		val result = requireListener().onDescriptorReadRequest(descriptor)

		sendResponse(
			device,
			requestId,
			if (result.isSuccessful) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE,
			0,
			result.data
		)
	}

	override fun onDescriptorWriteRequest(
		device: BluetoothDevice,
		requestId: Int,
		descriptor: BluetoothGattDescriptor,
		preparedWrite: Boolean,
		responseNeeded: Boolean,
		offset: Int, value: ByteArray,
	) {
		// Ignore requests from devices other than the one we are currently connected with
		if (currentConnection?.address != device.address) {
			sendResponse(device, requestId, BluetoothGatt.GATT_WRITE_NOT_PERMITTED)
			return
		}

		val result = requireListener().onDescriptorWriteRequest(descriptor)
		if (responseNeeded) {
			sendResponse(
				device,
				requestId,
				if (result.isSuccessful) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE,
				0,
				result.data
			)
		}
	}

	override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
		negotiatedMtu = mtu
		requireListener().onMtuChanged(mtu)
	}

	override fun onNotificationSent(device: BluetoothDevice, status: Int) {
		if (status != BluetoothGatt.GATT_SUCCESS) {
			reportError(Error("Error in onNotificationSent status=$status"))
			return
		}
		drainWritingQueues()
	}

	private fun reportPeerConnected() {
		if (listener != null && !inhibitCallbacks) {
			requireListener().onPeerConnected()
		}
	}

	private fun reportPeerDisconnected() {
		if (listener != null && !inhibitCallbacks) {
			requireListener().onPeerDisconnected()
		}
	}

	private fun reportError(error: Throwable) {
		if (listener != null && !inhibitCallbacks) {
			requireListener().onError(error)
		}
	}

	private fun requireServer(): BluetoothGattServer {
		return gattServer ?: throw IllegalStateException("GattServer not set")
	}

	private fun requireListener(): BleGattServerListener {
		return listener ?: throw IllegalStateException("Listener not set")
	}

	private fun sendResponse(device: BluetoothDevice, requestId: Int, status: Int, offset: Int = 0, value: ByteArray? = null) {
		try {
			gattServer?.sendResponse(device, requestId, status, offset, value)
		} catch (e: Exception) {
			reportError(e)
		}
	}

	private fun drainWritingQueues() {
		writingQueues.keys.forEach { drainWritingQueue(it) }
	}

	@Suppress("DEPRECATION")
	private fun drainWritingQueue(charUuid: UUID) {
		val chunk = writingQueues.getValue(charUuid).poll() ?: return

		if (chunk.size == 1 && chunk.single() == TransportProtocol.SHUTDOWN_MESSAGE.single()) {
			Logger(TAG).debug("Chunk is length 0, shutting down GattServer in 1000ms")
			// TODO: On some devices we lose messages already sent if we don't have a delay like
			//  this. Need to properly investigate if this is a problem in our stack or the
			//  underlying BLE subsystem.
			Thread.sleep(1000)
			Logger(TAG).debug("Shutting down GattServer now")

			try {
				if (currentConnection != null) {
					requireServer().cancelConnection(currentConnection)
				}
				requireServer().close()
			} catch (e: SecurityException) {
				Logger(TAG).error("Caught SecurityException while shutting down", e)
			} finally {
				gattServer = null
			}
		} else {
			val characteristic = characteristics.singleOrNull { it.uuid?.toJavaUuid() == charUuid }?.characteristic
			if (characteristic == null) {
				reportError(Error("No characteristic found for UUID $charUuid"))
				return
			}

			val connection = currentConnection ?: run {
				reportError(Error("Currently not connected"))
				return
			}

			try {
				val success = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
					val result = requireServer().notifyCharacteristicChanged(connection, characteristic, false, chunk)
					result == BluetoothStatusCodes.SUCCESS
				} else {
					characteristic.value = chunk
					requireServer().notifyCharacteristicChanged(connection, characteristic, false)
				}

				if (!success) {
					reportError(Error("Error calling notifyCharacteristicsChanged on characteristic $charUuid"))
					return
				}
			} catch (e: SecurityException) {
				reportError(e)
			}
		}
	}
}
