package ch.ubique.heidi.proximity.protocol.mdl

import ch.ubique.heidi.util.extensions.toCbor
import uniffi.heidi_util_rust.Value

class MdlCapabilities(val capabilities: Map<Int, MdlCapability>) {
	companion object {
		const val DC_API_CAPABILITY_KEY: Int = 0x44437631
	}

	fun getValue() : Value {
		var cborMap = mutableMapOf<Int, Value>()
		for( (key, value) in this.capabilities ) {
			cborMap.put(key, value.getValue())
		}
		return cborMap.toCbor()
	}
}
interface MdlCapability {
	fun getValue() : Value
}

data class DcApiCapability(public val supportedProtocols: List<String>) : MdlCapability {
	override fun getValue() =  supportedProtocols.toCbor()

}
