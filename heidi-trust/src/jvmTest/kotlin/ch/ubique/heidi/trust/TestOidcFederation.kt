package ch.ubique.heidi.trust.framework.oidcfederation

import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadata
import ch.ubique.heidi.issuance.metadata.data.CredentialIssuerMetadataClaims
import ch.ubique.heidi.trust.model.AgentInformation
import kotlin.test.Test
import kotlin.test.*
import kotlinx.coroutines.test.runTest
import ch.ubique.heidi.presentation.request.PresentationRequest
import ch.ubique.heidi.trust.model.AgentType


class TestOidcFederation {

    suspend fun getIssuerInformationZVV(
        framework: OidcFederationTrustFramerwork,
        credentialConfigurationIds: List<String> = listOf("zvv-memberkarte-a6thx-1.2.0-sd-jwt")
    ): AgentInformation? {
        return framework.getIssuerInformation(
            "https://heidi-issuer-ws-dev.ubique.ch/zvv/c",
            credentialConfigurationIds,
            CredentialIssuerMetadata.Unsigned(CredentialIssuerMetadataClaims(
                credentialIssuer = "https://heidi-issuer-ws-dev.ubique.ch/zvv/c",
                credentialEndpoint = "",
                credentialConfigurationsSupported = mapOf()
            ))
        );
    }

    @Test
    fun `ZVV trusted`() = runTest {
        val framework = OidcFederationTrustFramerwork();
        val agentInfo = getIssuerInformationZVV(framework);
        assertNotNull(agentInfo)
        agentInfo?.let {
            assertEquals(AgentType.ISSUER, it.type)
            assertTrue(it.isTrusted)
            assertTrue(it.isVerified)
            assertNotNull(it.logoUri)
            assertNotEquals("", it.logoUri, "Expected non-empty display logo")
            assertNotEquals("", it.displayName, "Expected non-empty display name")
        }
    }

    @Test
    fun `ZVV not trusted`() = runTest {
        val framework = OidcFederationTrustFramerwork(
            jwkTrustAnchorProvider = StaticJWKTrustAnchorProvider(trustAnchors = listOf())
        );
        val agentInfo = getIssuerInformationZVV(framework);
        assertNotNull(agentInfo)
        agentInfo?.let {
            assertEquals(AgentType.ISSUER, it.type)
            assertFalse(it.isTrusted)
            assertTrue(it.isVerified) // trust chain is valid, credential configuration ids check out
            assertNotNull(it.logoUri)
            assertNotEquals("", it.logoUri, "Expected non-empty display logo")
            assertNotEquals("", it.displayName, "Expected non-empty display name")
        }
    }

    @Test
    fun `ZVV invalid cred configuration id`() = runTest {
        val framework = OidcFederationTrustFramerwork();
        val agentInfo =
            getIssuerInformationZVV(framework, credentialConfigurationIds = listOf("fnord"));
        assertNotNull(agentInfo)
        agentInfo?.let {
            assertTrue(it.isTrusted)
            assertFalse(it.isVerified)
        }
    }

    @Test
    @Ignore("Test doesnt work, example JWT from openid-federation spec is not valid, thanks for nothing")
    fun `trust from presentation request`() = runTest {
        val framework = OidcFederationTrustFramerwork();
        val agentInfo = framework.getVerifierInformation(
            "https://op.example.org",
            PresentationRequest(clientId = "https://rp.example.com"),
            "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiUlMyNTYiLCJraWQiOiJOX19EOThJdkI4TmFlLWt3QTZuck90LWlwVGhqSGtEeDM3bmljRE1IM040In0.eyJhdWQiOiJodHRwczovL29wLmV4YW1wbGUub3JnIiwiY2xpZW50X2lkIjoiaHR0cHM6Ly9ycC5leGFtcGxlLmNvbSIsImV4cCI6MTU4OTY5OTE2MiwiaWF0IjoxNTg5Njk5MTAyLCJpc3MiOiJodHRwczovL3JwLmV4YW1wbGUuY29tIiwianRpIjoiNGQzZWMwZjgxZjEzNGVlOWE5N2UwNDQ5YmU2ZDMyYmUiLCJub25jZSI6IjRMWDBtRk14ZEJqa0dtdHg3YThXSU9uQiIsInJlZGlyZWN0X3VyaSI6Imh0dHBzOi8vcnAuZXhhbXBsZS5jb20vYXV0aHpfY2IiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwgYWRkcmVzcyBwaG9uZSIsInN0YXRlIjoiWW1YOFBNOUk3V2JOb01ubmllS0tCaXB0Vlcwc1AyT1oiLCJ0cnVzdF9jaGFpbiI6WyJleUpoYkdjaU9pSlNVekkxTmlJc0ltdHBaQ0k2SW1zMU5FaFJkRVJwWW5sSFkzTTVXbGRXVFdaMmFVaG0gLi4uIiwiZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklrSllkbVp5Ykc1b1FVMTFTRkl3TjJGcVZXMUJZMEpTIC4uLiIsImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJa0pZZG1aeWJHNW9RVTExU0ZJd04yRnFWVzFCWTBKUyAuLi4iXX0.Rv0isfuku0FcRFintgxgKDk7EnhFkpQRg3Tm6N6fCHAHEKFxVVdjy49JboJtxKcQVZKN9TKn3lEYM1wtF1e9PQrNt4HZ21ICfnzxXuNx1F5SY1GXCU2n2yFVKtz3N0YkAFbTStzy-sPRTXB0stLBJH74RoPiLs2c6dDvrwEv__GA7oGkg2gWt6VDvnfDpnvFi3ZEUR1J8MOeW_VFsayrT9sNjyjsz62Po4LzvQKQMKxq0dNwPNYuuSfUmb-YvmFguxDb3weYl8WS-48EIkP1h4b_KGU9x9n7a1fUOHrS02ATQZmaL8jUil7yLJqx5MiCsPr4pCAXV0doA4pwhs_FIw"
        );
        assertNotNull(agentInfo)
        agentInfo?.let {
            assertEquals(AgentType.VERIFIER, it.type)
            assertTrue(it.isTrusted)
            assertTrue(it.isVerified)
            assertNotEquals("", it.displayName, "Expected non-empty display name")
        }
    }
}