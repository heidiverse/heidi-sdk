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
package ch.ubique.heidi.proximity

enum class ProximityPhase {
	SCAN,
	CONNECT,
	SUBMIT,
}

enum class ProximityOperation {
	WRITE,
	WRITE_CHARACTERISTIC,
	WRITE_DESCRIPTOR,
	READ,
	READ_CHARACTERISTIC,
	READ_DESCRIPTOR,
}

sealed interface ProximityError {
	val message: String

	data class BluetoothUnavailable(
		val stateDescription: String
	) : ProximityError {
		override val message: String = "Bluetooth unavailable: $stateDescription"
	}

	data class Timeout(
		val phase: ProximityPhase,
		val timeoutMillis: Long
	) : ProximityError {
		override val message: String = "BLE ${phase.name} timed out after ${timeoutMillis / 1000} seconds"
	}

	data class MissingConnectedPeripheral(
		val operation: ProximityOperation
	) : ProximityError {
		override val message: String = "Cannot ${operation.name}: no connected peripheral"
	}

	data class CharacteristicNotFound(
		val operation: ProximityOperation
	) : ProximityError {
		override val message: String = "Cannot ${operation.name}: characteristic not found"
	}

	data class DescriptorNotFound(
		val operation: ProximityOperation
	) : ProximityError {
		override val message: String = "Cannot ${operation.name}: descriptor not found"
	}

	data object ConnectionFailed : ProximityError {
		override val message: String = "Failed to connect peripheral"
	}

	data object PeripheralDisconnected : ProximityError {
		override val message: String = "Peripheral disconnected with error"
	}

	data object ServiceDiscoveryFailed : ProximityError {
		override val message: String = "Failed to discover services"
	}

	data object CharacteristicDiscoveryFailed : ProximityError {
		override val message: String = "Failed to discover characteristics"
	}

	data object CharacteristicValueUpdateFailed : ProximityError {
		override val message: String = "Failed to update characteristic value"
	}

	data object DescriptorWriteFailed : ProximityError {
		override val message: String = "Failed to write descriptor"
	}

	data class InvalidData(
		val details: String
	) : ProximityError {
		override val message: String = details
	}

	data class InvalidState(
		val details: String
	) : ProximityError {
		override val message: String = details
	}

	data class Unknown(
		override val message: String
	) : ProximityError
}
