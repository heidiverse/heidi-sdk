package ch.ubique.heidi.proximity.protocol.mdl

import ch.ubique.heidi.util.extensions.toCbor
import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.encodeCbor

object MdlCoseKey {
	fun fromPublicKeyBytes(publicKey: ByteArray): Value {
		return mapOf(
			//ECDH
			-1 to 1,
			// EC
			1 to 2,
			//x
			-2 to publicKey.slice(1..<33).toByteArray(),
			//y
			-3 to publicKey.slice(33..<65).toByteArray(),
		).toCbor()
	}

	fun encodedFromPublicKeyBytes(publicKey: ByteArray): ByteArray {
		return encodeCbor(fromPublicKeyBytes(publicKey))
	}
}
