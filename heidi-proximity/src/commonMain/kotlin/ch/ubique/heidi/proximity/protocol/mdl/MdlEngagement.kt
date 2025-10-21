package ch.ubique.heidi.proximity.protocol.mdl

import ch.ubique.heidi.proximity.protocol.EngagementBuilder
import ch.ubique.heidi.util.extensions.asArray
import ch.ubique.heidi.util.extensions.asBoolean
import ch.ubique.heidi.util.extensions.asBytes
import ch.ubique.heidi.util.extensions.asOrderedObject
import ch.ubique.heidi.util.extensions.asString
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
			val deviceEngagementValue = decodeCbor(originalData)
			// verify version
			val deviceEngagement = deviceEngagementValue.asOrderedObject()
			val version = deviceEngagement!![Value.Number(JsonNumber.Integer(0))]

			//extract key
			val coseKey = deviceEngagement[Value.Number(JsonNumber.Integer(1))]
			val transportOptions = deviceEngagement[Value.Number(JsonNumber.Integer(2))]!!.asArray()!!
			val firstOption = transportOptions[0]
			// BLE options are the third element
			val bleOptions = firstOption[2].asOrderedObject()!!
			val peripheralServerModeSupported = bleOptions[Value.Number(JsonNumber.Integer(0))]
			val centralClientModeSupported = bleOptions[Value.Number(JsonNumber.Integer(1))]
			val centralClientUuid = if (centralClientModeSupported?.asBoolean() == true) {
				Uuid.fromByteArray(bleOptions[Value.Number(JsonNumber.Integer(11))]?.asBytes()!!)
			} else {
				null
			}
			val peripheralServerUuid = if (peripheralServerModeSupported?.asBoolean() == true) {
				Uuid.fromByteArray(bleOptions[Value.Number(JsonNumber.Integer(10))]?.asBytes()!!)
			} else {
				null
			}
			val capabilities = if(version?.asString() == "1.1") {
				// we could have capabilities
				deviceEngagement[Value.Number(JsonNumber.Integer(6))]?.asOrderedObject()?.let { capabilitiesObject ->
					val caps = mutableMapOf<Int, MdlCapability>()
					capabilitiesObject[Value.Number(JsonNumber.Integer(0x44437631))]?.let { dcApiCapability ->
						dcApiCapability.asArray()?.mapNotNull { it.asString() }?.let{
							caps.put(0x44437631, DcApiCapability(it))
						}

					}
					MdlCapabilities(caps)
				}
			} else {
				null
			}
			return MdlEngagement(
				coseKey = coseKey?.asBytes()!!,
				centralClientUuid,
				peripheralServerUuid,
				centralClientModeSupported = centralClientModeSupported?.asBoolean()!!,
				peripheralServerModeSupported = peripheralServerModeSupported?.asBoolean()!!,
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