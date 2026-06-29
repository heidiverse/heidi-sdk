package ch.ubique.heidi.util.json

import ch.ubique.heidi.credentials.W3C
import uniffi.heidi_crypto_rust.SoftwareKeyPair
import uniffi.heidi_util_rust.Value
import kotlin.test.Test

class OpenBadgesTest {
    @Test
    fun `Creating an verifying an OpenBadge Credential should work`() {
        val issuerKey = SoftwareKeyPair()

        val credential = W3C.OpenBadge303.create(
            claims = Value.Object(mapOf()),
            keyId = "",
            key = TestSigner(issuerKey)
        )


    }
}