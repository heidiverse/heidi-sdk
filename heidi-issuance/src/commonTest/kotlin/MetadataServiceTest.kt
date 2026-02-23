import ch.ubique.heidi.issuance.metadata.MetadataService
import kotlin.test.Test
import kotlin.test.assertEquals

class MetadataServiceTest {
    @Test
    fun testOidcCredentialIssuerEndpoint() {
        var url = MetadataService.oidcCredentialIssuerEndpoint("https://example.com/issuer")
        assertEquals("https://example.com/issuer/.well-known/openid-credential-issuer", url.toString())

        url = MetadataService.oidcCredentialIssuerEndpoint("https://example.com/issuer/")
        assertEquals("https://example.com/issuer/.well-known/openid-credential-issuer", url.toString())

        url = MetadataService.oidcCredentialIssuerEndpoint("https://example.com/issuer/path")
        assertEquals("https://example.com/issuer/path/.well-known/openid-credential-issuer", url.toString())

        url = MetadataService.oidcCredentialIssuerEndpoint("https://example.com/")
        assertEquals("https://example.com/.well-known/openid-credential-issuer", url.toString())

        url = MetadataService.oidcCredentialIssuerEndpoint("https://example.com")
        assertEquals("https://example.com/.well-known/openid-credential-issuer", url.toString())
    }

    @Test
    fun testIetfCredentialIssuerEndpoint() {
        var url = MetadataService.ietfCredentialIssuerEndpoint("https://example.com/issuer")
        assertEquals("https://example.com/.well-known/openid-credential-issuer/issuer", url.toString())

        url = MetadataService.ietfCredentialIssuerEndpoint("https://example.com/issuer/")
        assertEquals("https://example.com/.well-known/openid-credential-issuer/issuer/", url.toString())

        url = MetadataService.ietfCredentialIssuerEndpoint("https://example.com/issuer/path")
        assertEquals("https://example.com/.well-known/openid-credential-issuer/issuer/path", url.toString())

        url = MetadataService.ietfCredentialIssuerEndpoint("https://example.com/")
        assertEquals("https://example.com/.well-known/openid-credential-issuer", url.toString())

        url = MetadataService.ietfCredentialIssuerEndpoint("https://example.com")
        assertEquals("https://example.com/.well-known/openid-credential-issuer", url.toString())
    }
}