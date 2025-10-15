package ch.ubique.heidi.util.json

import ch.ubique.heidi.credentials.asSelector
import ch.ubique.heidi.credentials.get
import ch.ubique.heidi.dcql.DcqlClaimQueryResolver
import kotlinx.serialization.json.Json
import uniffi.heidi_credentials_rust.PointerPart
import uniffi.heidi_dcql_rust.ClaimsQuery
import uniffi.heidi_dcql_rust.CredentialQuery
import uniffi.heidi_util_rust.Value
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class DcqlClaimQueryResolverTest {

    private val credential: Value = Json.decodeFromString("""
        {
            "first_name": "John",
            "last_name": "Doe",
            "school": {
                "name": "Example University",
                "graduated": false
            }
        }
    """.trimIndent())

    private fun hasClaims(path: List<PointerPart>, values: List<Value>?): Boolean {
        val claim = credential[path.asSelector()]

        if (values == null)
            return claim.isNotEmpty()

        return values.any { v -> claim.any { c -> c == v  } }
    }

    @Test
    fun testSimple_success() {
        val claims = listOf(
            ClaimsQuery(path = listOf(
                PointerPart.String("first_name")
            )),
            ClaimsQuery(
                path = listOf(
                    PointerPart.String("school"),
                    PointerPart.String("graduated")
                ),
                values = listOf(Value.Boolean(false))
            ),
        )
        val query = CredentialQuery(
            id = "test",
            format = "test",
            claims = claims,
            claimSets = null,
        )

        val neededClaims = DcqlClaimQueryResolver.neededClaims(query, ::hasClaims)

        assertEquals(claims, neededClaims)
    }

    @Test
    fun testSimple_failure() {
        val claims = listOf(
            ClaimsQuery(path = listOf(
                PointerPart.String("first_name")
            )),
            ClaimsQuery(
                path = listOf(
                    PointerPart.String("school"),
                    PointerPart.String("graduated")
                ),
                values = listOf(Value.Boolean(true)) // <--- this doesn't exist
            ),
        )
        val query = CredentialQuery(
            id = "test",
            format = "test",
            claims = claims,
            claimSets = null,
        )

        val neededClaims = DcqlClaimQueryResolver.neededClaims(query, ::hasClaims)

        assertNull(neededClaims)
    }

    @Test
    fun testComplex_success() {
        val claimsSet1 = listOf(
            ClaimsQuery(
                id = "first-name",
                path = listOf(PointerPart.String("first_name"))
            ),
            ClaimsQuery(
                id = "last-name",
                path = listOf(PointerPart.String("last_name"))
            )
        )
        val claimsSet2 = listOf(
            ClaimsQuery(
                id = "graduated",
                path = listOf(
                    PointerPart.String("school"),
                    PointerPart.String("graduated")
                ),
                values = listOf(Value.Boolean(true))
            )
        )
        val query = CredentialQuery(
            id = "test",
            format = "test",
            claims = claimsSet1 + claimsSet2,
            claimSets = listOf(
                listOf("graduated"),
                listOf("first-name", "last-name")
            ),
        )

        val neededClaims = DcqlClaimQueryResolver.neededClaims(query, ::hasClaims)

        assertEquals(claimsSet1, neededClaims)
    }

    @Test
    fun testComplex_failure() {
        val claimsSet1 = listOf(
            ClaimsQuery(
                id = "first-name",
                path = listOf(PointerPart.String("first_name"))
            ),
            ClaimsQuery(
                id = "last-name",
                path = listOf(PointerPart.String("last_name")),
                values = listOf(Value.String("Woe"))
            )
        )
        val claimsSet2 = listOf(
            ClaimsQuery(
                id = "graduated",
                path = listOf(
                    PointerPart.String("school"),
                    PointerPart.String("graduated")
                ),
                values = listOf(Value.Boolean(true))
            )
        )
        val query = CredentialQuery(
            id = "test",
            format = "test",
            claims = claimsSet1 + claimsSet2,
            claimSets = listOf(
                listOf("graduated"),
                listOf("first-name", "last-name")
            ),
        )

        val neededClaims = DcqlClaimQueryResolver.neededClaims(query, ::hasClaims)

        assertNull(neededClaims)
    }
}