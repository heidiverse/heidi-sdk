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
import kotlin.uuid.Uuid

internal interface BleGattServer {
	fun setListener(listener: BleGattServerListener?)

	fun start(characteristics: List<BleGattCharacteristic>): Boolean

	fun startAdvertising(listener: BleAdvertiserListener)

	fun stopAdvertising()

	fun supportsSessionTermination(): Boolean

	fun stop()

	fun writeCharacteristic(charUuid: Uuid, data: ByteArray)
	fun writeCharacteristicNonChunked(charUuid: Uuid, data: ByteArray)

	val characteristicValueSize : Int
	fun chunkMessage(data: ByteArray, emitChunk: (ByteArray) -> Unit) {
		// Also need room for the leading 0x00 or 0x01.
		val maxDataSize = characteristicValueSize - 1
		var offset = 0
		do {
			val moreDataComing = offset + maxDataSize < data.size
			var size = data.size - offset
			if (size > maxDataSize) {
				size = maxDataSize
			}
			val chunk = ByteArray(size + 1)
			chunk[0] = if (moreDataComing) 0x01.toByte() else 0x00.toByte()
			data.copyInto(chunk, 1, offset, offset + size)
			emitChunk(chunk)
			offset += size
		} while (offset < data.size)
	}
}

internal sealed interface ChunkProcessingResult {
	data class Complete(val payload: ByteArray) : ChunkProcessingResult
	data class Single(val payload: ByteArray) : ChunkProcessingResult
	object Waiting : ChunkProcessingResult
}

internal class ChunkAccumulator<K> {
	private val buffers = mutableMapOf<K, ChunkBuffer>()

	fun consume(key: K, packet: ByteArray): ChunkProcessingResult {
		if (packet.size == 1 && key !in buffers) {
			return ChunkProcessingResult.Single(packet)
		}
		val header = packet.firstOrNull()?.toInt() ?: return ChunkProcessingResult.Single(packet)
		return when (header) {
			0x00 -> {
				val payload = if (packet.size > 1) packet.copyOfRange(1, packet.size) else ByteArray(0)
				val buffer = buffers.getOrPut(key) { ChunkBuffer() }
				buffer.append(payload)
				val complete = buffer.takeAll()
				buffers.remove(key)
				ChunkProcessingResult.Complete(complete)
			}
			0x01 -> {
				val payload = if (packet.size > 1) packet.copyOfRange(1, packet.size) else ByteArray(0)
				buffers.getOrPut(key) { ChunkBuffer() }.append(payload)
				ChunkProcessingResult.Waiting
			}
			else -> ChunkProcessingResult.Single(packet)
		}
	}

	fun clear(key: K) {
		buffers.remove(key)
	}

	fun clear() {
		buffers.clear()
	}

	private class ChunkBuffer {
		private val data = mutableListOf<Byte>()

		fun append(bytes: ByteArray) {
			if (bytes.isEmpty()) return
			bytes.forEach { data.add(it) }
		}

		fun takeAll(): ByteArray {
			val result = ByteArray(data.size)
			data.forEachIndexed { index, byte -> result[index] = byte }
			data.clear()
			return result
		}
	}
}
