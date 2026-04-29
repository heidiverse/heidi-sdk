package ch.ubique.heidi.proximity.protocol.mdl

import ch.ubique.heidi.util.extensions.toCbor
import uniffi.heidi_crypto_rust.KeyType
import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.encodeCbor

object MdlCoseKey {
	fun fromPublicKeyBytes(publicKey: ByteArray, keyType: KeyType): Value {
		// elliptic curve keys with x and y
		var kty = 2
		// NIST P-256 curve
		// See https://www.rfc-editor.org/rfc/rfc9053#section-7.1 for all values
		var crv = 1
		var x = ByteArray(0)
		var y = ByteArray(0)

		when(keyType) {
			KeyType.P256 -> {
				if(publicKey.size != 65) {
					return Value.Null
				}
				x = publicKey.slice(1..<33).toByteArray()
				y = publicKey.slice(33..<65).toByteArray()
			}
			KeyType.P384 -> {
				if(publicKey.size != 97) {
					return Value.Null
				}
				crv = 2
				x = publicKey.slice(1..<49).toByteArray()
				y = publicKey.slice(49..<97).toByteArray()
			}
			KeyType.P521 -> {
				if(publicKey.size != 137) {
					return Value.Null
				}
				crv = 3
				x = publicKey.slice(1..<67).toByteArray()
				y = publicKey.slice(67..<133).toByteArray()
			}
			KeyType.ED25519 -> {
				if(publicKey.size != 32) {
					return Value.Null
				}
				// OKP
				kty = 1
				// X25519 (only used for DH)
				crv = 4
				x = publicKey
			}
		}
		return when(kty) {
			// https://datatracker.ietf.org/doc/html/rfc9679#name-octet-key-pair-okp
			1 -> {
				mapOf(
					1 to kty,
					-1 to crv,
					-2 to x,
				).toCbor()
			}
			// https://datatracker.ietf.org/doc/html/rfc9679#name-elliptic-curve-keys-with-x-
			2 -> {
				mapOf(
					1 to kty,
					-1 to crv,
					-2 to x,
					-3 to y,
				).toCbor()
			}
			else -> Value.Null
		}
	}

	fun encodedFromPublicKeyBytes(publicKey: ByteArray, keyType: KeyType): ByteArray {
		return encodeCbor(fromPublicKeyBytes(publicKey, keyType))
	}
}
