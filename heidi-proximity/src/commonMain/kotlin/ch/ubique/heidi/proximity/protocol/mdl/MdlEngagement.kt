package ch.ubique.heidi.proximity.protocol.mdl

import ch.ubique.heidi.proximity.protocol.EngagementBuilder
import ch.ubique.heidi.util.extensions.asArray
import ch.ubique.heidi.util.extensions.asBoolean
import ch.ubique.heidi.util.extensions.asBytes
import ch.ubique.heidi.util.extensions.asOrderedObject
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.asTag
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.toCbor
import uniffi.heidi_crypto_rust.base64UrlDecode
import uniffi.heidi_crypto_rust.base64UrlEncode
import uniffi.heidi_util_rust.JsonNumber
import uniffi.heidi_util_rust.Value
import uniffi.heidi_util_rust.decodeCbor
import uniffi.heidi_util_rust.encodeCbor
import kotlin.uuid.Uuid

data class MdlEngagement(val coseKey: ByteArray,
						 val centralClientUuid: Uuid?,
						 val peripheralServerUuid: Uuid?,
						 val centralClientModeSupported: Boolean,
						 val peripheralServerModeSupported: Boolean,
						 val capabilities: MdlCapabilities? = null,
						 val originalData : ByteArray) : EngagementBuilder {
	companion object {
		fun fromQrCode(qrcodeData: String) : MdlEngagement? {
			val originalData = base64UrlDecode(qrcodeData)
			return fromCbor(originalData)
	}
	fun fromCbor(originalData: ByteArray) : MdlEngagement? {
		val deviceEngagementValue = decodeCbor(originalData)
		// verify version
		val deviceEngagement = deviceEngagementValue.asOrderedObject()
		val version = deviceEngagement!![Value.Number(JsonNumber.Integer(0))]

		//extract key
		val coseKey = deviceEngagement[Value.Number(JsonNumber.Integer(1))]
		val transportOptions = deviceEngagement[Value.Number(JsonNumber.Integer(2))]?.asArray()
		var centralClientUuid : Uuid? = null
		var peripheralServerUuid : Uuid? = null
		var centralClientModeSupported : Value? = null
		var peripheralServerModeSupported : Value?  = null
		if(transportOptions != null) {
			val firstOption = transportOptions[0]
			// BLE options are the third element
			val bleOptions = firstOption[2].asOrderedObject()!!
			val peripheralServerModeSupported = bleOptions[Value.Number(JsonNumber.Integer(0))]
			centralClientModeSupported = bleOptions[Value.Number(JsonNumber.Integer(1))]
			centralClientUuid = if (centralClientModeSupported?.asBoolean() == true) {
				bleOptions[Value.Number(JsonNumber.Integer(11))]?.asBytes()?.let {
					Uuid.fromByteArray(it)
				}
			} else {
				null
			}
			peripheralServerUuid = if (peripheralServerModeSupported?.asBoolean() == true) {
				bleOptions[Value.Number(JsonNumber.Integer(10))]?.asBytes()?.let {
					Uuid.fromByteArray(it)
				}
			} else {
				null
			}
		}

		val capabilities = if(version?.asString() == "1.1") {
			// we could have capabilities
			deviceEngagement[Value.Number(JsonNumber.Integer(6))]?.asOrderedObject()?.let { capabilitiesObject ->
				val caps = mutableMapOf<Int, MdlCapability>()
				capabilitiesObject[Value.Number(JsonNumber.Integer(MdlCapabilities.DC_API_CAPABILITY_KEY))]?.let { dcApiCapability ->
					dcApiCapability.asArray()?.mapNotNull { it.asString() }?.let{
						caps.put(MdlCapabilities.DC_API_CAPABILITY_KEY, DcApiCapability(it))
					}

				}
				MdlCapabilities(caps)
			}
		} else {
			null
		}
		return MdlEngagement(
			coseKey = coseKey?.get(1)?.asTag()?.value?.get(0)?.asBytes()!!,
			centralClientUuid,
			peripheralServerUuid,
			centralClientModeSupported = centralClientModeSupported?.asBoolean() ?: run { false },
			peripheralServerModeSupported = peripheralServerModeSupported?.asBoolean()?: run { false },
			capabilities = capabilities,
			originalData
		)
	}
	}

	fun getEngagementBytes() : ByteArray {
		val bleOptions = mutableMapOf<Int, Any>()
		bleOptions.put(0, peripheralServerModeSupported)
		bleOptions.put(1, centralClientModeSupported)
		if(peripheralServerModeSupported && peripheralServerUuid != null) {
			bleOptions.put(10, peripheralServerUuid.toByteArray())
		}
		if(centralClientModeSupported && centralClientUuid != null) {
			bleOptions.put(11, centralClientUuid)
		}
		val deviceEngagement = mutableMapOf(
			0 to "1.1",
			1 to listOf(
				1,
				24 to coseKey.toCbor()
			),
			2 to listOf(
				listOf(
					2,
					1,
					bleOptions
				)
			)
		)
		capabilities?.let {
			deviceEngagement.put(6, capabilities.getValue())
		}
		return encodeCbor(deviceEngagement.toCbor())
	}

	override fun createQrCodeForEngagement(): String {
		return base64UrlEncode(originalData)
	}
}
