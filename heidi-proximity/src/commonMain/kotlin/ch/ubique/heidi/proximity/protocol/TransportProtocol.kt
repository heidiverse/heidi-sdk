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
package ch.ubique.heidi.proximity.protocol

import ch.ubique.heidi.util.log.Logger

abstract class TransportProtocol(
	val role: Role,
) {

	enum class Role {
		/** This device acts as the wallet during the connection */
		WALLET,

		/** This device acts as the verifier during the connection */
		VERIFIER,
	}

	companion object {
		/** An empty message to be sent as a ping */
		internal val EMPTY_MESSAGE = ByteArray(0)

		/** A custom message used to indicate a shutdown of the connection */
		internal val SHUTDOWN_MESSAGE = byteArrayOf(0x7F)
	}

	private var inhibitCallbacks = false
	private var listener: Listener? = null
	private val messageReceivedQueue = ArrayDeque<ByteArray>()

	var isConnected = false
		private set

	abstract suspend fun connect()

	abstract fun disconnect()

	abstract fun sendMessage(data: ByteArray, onProgress: ((sent: Int, total: Int) -> Unit)? = null)

	abstract fun sendTransportSpecificTerminationMessage()

	abstract fun supportsTransportSpecificTerminationMessage(): Boolean

	open fun getMessage(): ByteArray? = messageReceivedQueue.removeFirstOrNull()

	open fun setListener(listener: Listener) {
		this.listener = listener
	}

	// Should be called by disconnect() in subclasses to signal that no callbacks should be made
	// from here on.
	protected fun inhibitCallbacks() {
		inhibitCallbacks = true
	}

	protected fun reportConnecting() {
		if (!inhibitCallbacks) {
			listener?.onConnecting()
		}
	}

	protected fun reportConnected() {
		Logger.debug("Transport Protocol report Connected")
		if(isConnected) {
			return
		}
		isConnected = true

		if (!inhibitCallbacks) {
			listener?.onConnected()
		}
	}

	protected fun reportDisconnected() {
		isConnected = false
		if (!inhibitCallbacks) {
			listener?.onDisconnected()
		}
	}

	protected fun reportMessageReceived(data: ByteArray) {
		messageReceivedQueue.add(data)
		Logger.debug("reportMessageReceived: ${data.size} queue has now ${messageReceivedQueue.size} entries")
		if (!inhibitCallbacks) {
			listener?.onMessageReceived()
		}
	}

	protected fun reportTransportSpecificSessionTermination() {
		if (!inhibitCallbacks) {
			listener?.onTransportSpecificSessionTermination()
		}
	}

	protected fun reportError(error: Throwable) {
		if (!inhibitCallbacks) {
			listener?.onError(error)
		}
	}

	interface Listener {
		fun onConnecting()

		fun onConnected()

		fun onDisconnected()

		fun onMessageReceived()

		fun onTransportSpecificSessionTermination()

		fun onError(error: Throwable)
	}

}
