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
import ch.ubique.heidi.proximity.ConnectionTimeoutDefaults
import ch.ubique.heidi.proximity.ProximityError
import ch.ubique.heidi.proximity.ProximityOperation
import ch.ubique.heidi.proximity.ProximityPhase
import ch.ubique.heidi.util.extensions.toData
import ch.ubique.heidi.util.log.Logger
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import platform.CoreBluetooth.*
import platform.darwin.DISPATCH_QUEUE_SERIAL
import platform.darwin.NSObject
import platform.darwin.dispatch_async
import platform.darwin.dispatch_queue_create
import platform.darwin.dispatch_get_main_queue
import kotlin.uuid.Uuid

@OptIn(ExperimentalForeignApi::class)
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
	private val writeQueue = dispatch_queue_create("ch.ubique.heidi.proximity.GattClient.writeQueue", null)
	private val connectionTimeoutMillis = ConnectionTimeoutDefaults.BLE_CONNECTION_TIMEOUT_MILLIS
	private val timeoutScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
	private var connectionTimeoutJob: Job? = null
	private var scanStartJob: Job? = null

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
		val currentManager = manager
		if (currentManager == null) {
			reportConnectionError(ProximityError.BluetoothUnavailable("central manager is null"))
			return
		}
		startConnectionTimeout(ProximityPhase.SCAN)
		scanStartJob?.cancel()

		val state = currentManager.state
		Logger("GattClient").debug("startScanning requested, state=${describeCentralState(state)}, isReady=$isReady")
		if (state == CBManagerStatePoweredOn && isReady) {
			startScanNow(currentManager)
			return
		}
		if (isTerminalUnavailableState(state)) {
			reportConnectionError(ProximityError.BluetoothUnavailable(describeCentralState(state)))
			cleanupConnectionAttempt()
			return
		}
		scanStartJob = timeoutScope.launch {
			while (connectionTimeoutJob != null) {
				val latestManager = manager ?: return@launch
				val latestState = latestManager.state
				if (latestState == CBManagerStatePoweredOn && isReady) {
					dispatch_async(dispatch_get_main_queue()) {
						startScanNow(latestManager)
					}
					return@launch
				}
				if (isTerminalUnavailableState(latestState)) {
					dispatch_async(dispatch_get_main_queue()) {
						reportConnectionError(ProximityError.BluetoothUnavailable(describeCentralState(latestState)))
						cleanupConnectionAttempt()
					}
					return@launch
				}
				delay(150)
			}
		}
	}

	override fun stopScanning() {
		runCatching { manager?.stopScan() }
			.onFailure { reportConnectionError(ProximityError.Unknown(it.message ?: it::class.simpleName ?: "Unknown error")) }
	}

	override fun supportsSessionTermination(): Boolean {
		return true
	}

	override fun disconnect() {
		cancelConnectionTimeout()
		connectedPeripheral?.let {
			runCatching { manager?.cancelPeripheralConnection(it) }
				.onFailure { reportConnectionError(ProximityError.Unknown(it.message ?: it::class.simpleName ?: "Unknown error")) }
		}

		connectedPeripheral = null
		pendingWrites.clear()
	}

	override fun readCharacteristic(charUuid: Uuid) {
		val peripheral = connectedPeripheral ?: run {
			reportConnectionError(ProximityError.MissingConnectedPeripheral(ProximityOperation.READ_CHARACTERISTIC))
			return
		}
		val characteristic = peripheralCharacteristics[peripheral]
			?.find { it.uuid == charUuid }
			?: run {
				reportConnectionError(ProximityError.CharacteristicNotFound(ProximityOperation.READ))
				return
			}
		peripheral.readValueForCharacteristic(characteristic.characteristic)
	}

	override fun writeCharacteristic(
		charUuid: Uuid,
		data: ByteArray,
		onProgress: ((sent: Int, total: Int) -> Unit)?
	) {
		Logger("GattClient").debug("write chunked: $charUuid (${data.size})")
		val progress = onProgress?.let { WriteProgress(total = data.size, onProgress = it) }
		val peripheral = connectedPeripheral ?: run {
			reportConnectionError(ProximityError.MissingConnectedPeripheral(ProximityOperation.WRITE_CHARACTERISTIC))
			return
		}
		val characteristic = peripheralCharacteristics[peripheral]
			?.find { it.uuid == charUuid }
			?: run {
				reportConnectionError(ProximityError.CharacteristicNotFound(ProximityOperation.WRITE))
				return
			}
		chunkMessage(data) { chunk ->
			val payloadSize = (chunk.size - 1).coerceAtLeast(0)
			enqueueWrite(characteristic.characteristic, chunk, progress, payloadSize)
		}
	}

	override fun writeCharacteristicNonChunked(
		charUuid: Uuid,
		data: ByteArray,
		onProgress: ((sent: Int, total: Int) -> Unit)?
	) {
		Logger("GattClient").debug("write non chunked: $charUuid (${data.size})")
		val progress = onProgress?.let { WriteProgress(total = data.size, onProgress = it) }
		val peripheral = connectedPeripheral ?: run {
			reportConnectionError(ProximityError.MissingConnectedPeripheral(ProximityOperation.WRITE_CHARACTERISTIC))
			return
		}
		val characteristic = peripheralCharacteristics[peripheral]
			?.find { it.uuid == charUuid }
			?: run {
				reportConnectionError(ProximityError.CharacteristicNotFound(ProximityOperation.WRITE))
				return
			}
		enqueueWrite(characteristic.characteristic, data, progress, data.size)
	}

	override fun readDescriptor(charUuid: Uuid, descriptorUuid: Uuid) {
		val peripheral = connectedPeripheral ?: run {
			reportConnectionError(ProximityError.MissingConnectedPeripheral(ProximityOperation.READ_DESCRIPTOR))
			return
		}
		val characteristic = peripheralCharacteristics[peripheral]
			?.find { it.uuid == charUuid }
			?: run {
				reportConnectionError(ProximityError.CharacteristicNotFound(ProximityOperation.READ_DESCRIPTOR))
				return
			}
		val descriptor = characteristic.descriptors
			?.map { it as CBDescriptor }
			?.find { it.UUID.UUIDString.lowercase() == descriptorUuid.toString().lowercase() }
			?: run {
				reportConnectionError(ProximityError.DescriptorNotFound(ProximityOperation.READ))
				return
			}
		peripheral.readValueForDescriptor(descriptor)
	}

	override fun writeDescriptor(charUuid: Uuid, descriptorUuid: Uuid, data: ByteArray) {
		val peripheral = connectedPeripheral ?: run {
			reportConnectionError(ProximityError.MissingConnectedPeripheral(ProximityOperation.WRITE_DESCRIPTOR))
			return
		}
		val characteristic = peripheralCharacteristics[peripheral]
			?.find { it.uuid == charUuid }
			?: run {
				reportConnectionError(ProximityError.CharacteristicNotFound(ProximityOperation.WRITE_DESCRIPTOR))
				return
			}
		val descriptor = characteristic.descriptors
			?.map { it as CBDescriptor }
			?.find { it.UUID.UUIDString.lowercase() == descriptorUuid.toString().lowercase() }
			?: run {
				reportConnectionError(ProximityError.DescriptorNotFound(ProximityOperation.WRITE))
				return
			}
		peripheral.writeValue(data.toData(), descriptor)
	}

	internal fun notifyReadyToSend(peripheral: CBPeripheral) {
		if (peripheral != connectedPeripheral) {
			return
		}
		// serialize on writeQueue to avoid concurrent deque mutations
		dispatch_async(writeQueue) {
			flushPendingWritesLocked()
		}
	}

	internal fun onPeripheralDisconnected(peripheral: CBPeripheral) {
		if (peripheral != connectedPeripheral) {
			return
		}
		cancelConnectionTimeout()
		dispatch_async(writeQueue) {
			pendingWrites.clear()
		}
		connectedPeripheral = null
		incomingMessages.clear()
		listener?.onPeerDisconnected()
	}

	internal fun onConnectionAttemptStarted() {
		startConnectionTimeout(ProximityPhase.CONNECT)
	}

	internal fun onPeerConnectedReady() {
		cancelConnectionTimeout()
	}

	internal fun reportConnectionError(error: ProximityError) {
		cancelConnectionTimeout()
		listener?.onError(error)
	}

	internal fun onCentralStateChanged(state: Long) {
		isReady = state == CBManagerStatePoweredOn
		Logger("GattClient").debug("central state changed to ${describeCentralState(state)}, isReady=$isReady")
		if (isReady) {
			return
		}
		if (!hasActiveConnectionAttempt()) {
			return
		}
		if (state == CBManagerStateUnknown || state == CBManagerStateResetting) {
			Logger("GattClient").debug("central state ${describeCentralState(state)} while connecting, waiting for readiness")
			return
		}
		reportConnectionError(
			ProximityError.BluetoothUnavailable(describeCentralState(state))
		)
		cleanupConnectionAttempt()
	}

	private fun hasActiveConnectionAttempt(): Boolean {
		return connectionTimeoutJob != null || connectedPeripheral != null || manager?.isScanning == true
	}

	private fun cleanupConnectionAttempt() {
		scanStartJob?.cancel()
		scanStartJob = null
		runCatching { manager?.stopScan() }
		connectedPeripheral?.let { peripheral ->
			runCatching { manager?.cancelPeripheralConnection(peripheral) }
		}
		connectedPeripheral = null
		dispatch_async(writeQueue) {
			pendingWrites.clear()
		}
		incomingMessages.clear()
	}

	private fun startConnectionTimeout(phase: ProximityPhase) {
		cancelConnectionTimeout()
		connectionTimeoutJob = timeoutScope.launch {
			delay(connectionTimeoutMillis)
			Logger("GattClient").warn("BLE ${phase.name.lowercase()} timed out after ${connectionTimeoutMillis / 1000}s")
			dispatch_async(dispatch_get_main_queue()) {
				cleanupConnectionAttempt()
				listener?.onError(
					ProximityError.Timeout(phase = phase, timeoutMillis = connectionTimeoutMillis)
				)
			}
		}
	}

	private fun cancelConnectionTimeout() {
		connectionTimeoutJob?.cancel()
		connectionTimeoutJob = null
		scanStartJob?.cancel()
		scanStartJob = null
	}

	private fun startScanNow(currentManager: CBCentralManager) {
		Logger("GattClient").debug("starting BLE scan for service=$serviceUuid")
		runCatching {
			currentManager.scanForPeripheralsWithServices(listOf(CBUUID.UUIDWithString(serviceUuid.toString())), null)
		}.onFailure {
			reportConnectionError(ProximityError.Unknown(it.message ?: it::class.simpleName ?: "Unknown error"))
		}
	}

	private fun isTerminalUnavailableState(state: Long): Boolean {
		return state == CBManagerStatePoweredOff ||
			state == CBManagerStateUnauthorized ||
			state == CBManagerStateUnsupported
	}

	private fun enqueueWrite(
		characteristic: CBCharacteristic,
		payload: ByteArray,
		progress: WriteProgress? = null,
		payloadSize: Int = payload.size
	) {
		dispatch_async(writeQueue) {
			pendingWrites.addLast(PendingWrite(characteristic, payload, progress, payloadSize))
			flushPendingWritesLocked()
		}
	}

	private fun flushPendingWrites() {
		dispatch_async(writeQueue) {
			flushPendingWritesLocked()
		}
	}

	private fun flushPendingWritesLocked() {
		val peripheral = connectedPeripheral ?: return
		while (pendingWrites.isNotEmpty()) {
			val next = pendingWrites.first()
			if (!peripheral.canSendWriteWithoutResponse()) {
				return
			}
			pendingWrites.removeFirst()
			peripheral.writeValue(next.payload.toData(), next.characteristic, CBCharacteristicWriteWithoutResponse)
			next.progress?.advance(next.payloadSize)

			if (pendingWrites.isEmpty()) {
				listener?.onCharacteristicWrite(BleGattCharacteristic(next.characteristic))
			}
		}
	}

	private data class PendingWrite(
		val characteristic: CBCharacteristic,
		val payload: ByteArray,
		val progress: WriteProgress? = null,
		val payloadSize: Int = payload.size,
	)

	private class WriteProgress(
		private val total: Int,
		private val onProgress: ((sent: Int, total: Int) -> Unit)?
	) {
		private var sent: Int = 0

		fun advance(by: Int) {
			if (total <= 0) {
				onProgress?.invoke(1, 1)
				return
			}
			sent = (sent + by).coerceAtMost(total)
			onProgress?.invoke(sent, total)
		}
	}

	private fun describeCentralState(state: Long): String = when (state) {
		CBManagerStateUnknown -> "unknown"
		CBManagerStateResetting -> "resetting"
		CBManagerStateUnsupported -> "unsupported"
		CBManagerStateUnauthorized -> "unauthorized"
		CBManagerStatePoweredOff -> "poweredOff"
		CBManagerStatePoweredOn -> "poweredOn"
		else -> "state=$state"
	}
}
