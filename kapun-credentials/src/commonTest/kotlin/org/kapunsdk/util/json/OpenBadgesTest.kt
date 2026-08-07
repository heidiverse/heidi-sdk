package org.kapunsdk.util.json

import org.kapunsdk.credentials.W3C
import uniffi.kapun_crypto_rust.SoftwareKeyPair
import uniffi.kapun_util_rust.Value
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