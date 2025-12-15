package ch.ubique.heidi.proximity.util

import ch.ubique.heidi.util.log.Logger
import kotlin.math.min
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_crypto_rust.sha256Rs

private const val PREVIEW_BYTES = 10

internal fun logPayloadDebug(label: String, data: ByteArray) {
	if (data.isEmpty()) {
		Logger.debug("$label size=0 (empty payload)")
		return
	}
	val hash = base64UrlEncode(sha256Rs(data))
	val head = data.toHexSlice(0, min(PREVIEW_BYTES, data.size))
	val tail = if (data.size > PREVIEW_BYTES) {
		data.toHexSlice(data.size - min(PREVIEW_BYTES, data.size), min(PREVIEW_BYTES, data.size))
	} else {
		head
	}
	Logger.debug("$label size=${data.size} sha256=$hash head=$head tail=$tail")
}

private fun ByteArray.toHexSlice(start: Int, length: Int): String {
	if (isEmpty() || length <= 0) return ""
	val actualStart = start.coerceIn(0, size - 1)
	val actualLength = min(length, size - actualStart)
	val builder = StringBuilder(actualLength * 2)
	for (i in 0 until actualLength) {
		val value = this[actualStart + i].toInt() and 0xFF
		builder.append(value.toString(16).padStart(2, '0'))
	}
	return builder.toString()
}
