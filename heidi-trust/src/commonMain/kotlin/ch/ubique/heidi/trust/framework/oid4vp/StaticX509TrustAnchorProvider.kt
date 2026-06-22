/* Copyright 2025 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

package ch.ubique.heidi.trust.framework.oid4vp

import ch.ubique.heidi.trust.framework.X509TrustAnchorProvider
import io.ktor.util.decodeBase64Bytes
import uniffi.heidi_crypto_rust.X509Certificate
import uniffi.heidi_crypto_rust.extractCerts

class StaticX509TrustAnchorProvider: X509TrustAnchorProvider {
    private val trustAnchors : MutableList<X509Certificate> = mutableListOf(
        extractCerts("MIIBZjCCAQygAwIBAgIGAZGJt173MAoGCCqGSM49BAMCMB8xHTAbBgNVBAMMFGh0dHBzOi8vYXV0aG9yaXR5LmNoMB4XDTI0MDgyNTEzMjYyMVoXDTI1MDgyNTEzMjYyMVowHzEdMBsGA1UEAwwUaHR0cHM6Ly9hdXRob3JpdHkuY2gwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAScIjAmHrkp3TC6bisgaqmszbKkpY0iGTdHF2rcRemJCV+ikotDt7G+ApwG0m6fxt8aBJHeJ2mssLvZBmZj5LtWozQwMjAfBgNVHREEGDAWghRodHRwczovL2F1dGhvcml0eS5jaDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCpQsxyQx/5knqhGnDCiAo6MpQmTCd7vA9WehF4/1P8/QIgEnAtFVTP1uThuTEna1RD4Ji35+z1h8pDoMyLPd3Uaig=".decodeBase64Bytes())[0],
        extractCerts("MIIBzzCCAXWgAwIBAgIQVwAFolWQim94gmyCic3bCTAKBggqhkjOPQQDAjAdMQ4wDAYDVQQDEwVBbmltbzELMAkGA1UEBhMCTkwwHhcNMjQwNTAyMTQyMzMwWhcNMjgwNTAyMTQyMzMwWjAdMQ4wDAYDVQQDEwVBbmltbzELMAkGA1UEBhMCTkwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQC/YyBpcRQX8ZXpHfra1TNdSbS7qzgHYHJ3msbIr8TJLPNZI8Ul8zJlFdQVIVls5+5ClCbN+J9FUvhPGs4AzA+o4GWMIGTMB0GA1UdDgQWBBQv3zBo1i/1CfEgdvkIWDGO9lS1SzAOBgNVHQ8BAf8EBAMCAQYwIQYDVR0SBBowGIYWaHR0cHM6Ly9mdW5rZS5hbmltby5pZDASBgNVHRMBAf8ECDAGAQH/AgEAMCsGA1UdHwQkMCIwIKAeoByGGmh0dHBzOi8vZnVua2UuYW5pbW8uaWQvY3JsMAoGCCqGSM49BAMCA0gAMEUCIQCTg80AmqVHJLaZt2uuhAtPqKIXafP2ghtd9OCmdD51ZwIgKvVkrgTYlxSRAbmKY6MlkH8mM3SNcnEJk9fGVwJG++0=".decodeBase64Bytes())[0],
        extractCerts("MIIB2DCCAX+gAwIBAgIUfDkhpVn+pztfi9GLUzZtN3WA+nMwCgYIKoZIzj0EAwIwOjEQMA4GA1UEAwwHUm9vdCBDQTEZMBcGA1UECgwQUmVkY2FyZSBQaGFybWFjeTELMAkGA1UEBhMCREUwHhcNMjUwODI1MTMwMDI3WhcNMzUwODI0MTMwMDI3WjA6MRAwDgYDVQQDDAdSb290IENBMRkwFwYDVQQKDBBSZWRjYXJlIFBoYXJtYWN5MQswCQYDVQQGEwJERTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLQuU9pUZYHP8NiJCgOI1ihgSyHFlTyyfsBheEk6Dwczdnz/w6ChOTnOXIlq1HNc/1jtiz6KR+msTz4JwjEIEZSjYzBhMB0GA1UdDgQWBBSSij1JCTcU4CHNVJEIKgCYrhnFYjAfBgNVHSMEGDAWgBSSij1JCTcU4CHNVJEIKgCYrhnFYjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNHADBEAiBJK+lfAzSx6xKosqm5sEhJEKNsK/NACnYfeWXF8wr/rgIgLjhmUNPcwZrcEDLPAQR7g6o7xT9GdYZ/z6zWjIMotNI=".decodeBase64Bytes())[0],
        // https://playground.paradym.id/info
        extractCerts("MIICMzCCAdmgAwIBAgIQUIrWwRRwpN1wZkJ3kddlkTAKBggqhkjOPQQDAjAqMRswGQYDVQQDExJQYXJhZHltIFBsYXlncm91bmQxCzAJBgNVBAYTAk5MMB4XDTI2MDYwMzEwMjMwNVoXDTMxMDYwMzEwMjMwNVowKjEbMBkGA1UEAxMSUGFyYWR5bSBQbGF5Z3JvdW5kMQswCQYDVQQGEwJOTDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFLppN8WJtE5sYI8xjfV5y0wmPP+ZZANpbxsQIDjBm72/N2Z4XrzEesuR4mPqdJ/yzrPx3plR7jg1oUO8YGx3wOjgeAwgd0wHQYDVR0OBBYEFJGF8RBTTXxJM8R1X0MyDdmf0srGMA4GA1UdDwEB/wQEAwIBBjAoBgNVHRIEITAfhh1odHRwczovL3BsYXlncm91bmQucGFyYWR5bS5pZDASBgNVHRMBAf8ECDAGAQH/AgEAMG4GA1UdHwRnMGUwY6BhoF+GXWh0dHBzOi8vbWV0YWRhdGEucGFyYWR5bS5pZC9jZXJ0aWZpY2F0ZS1yZXZvY2F0aW9uLWxpc3RzL2ZlM2VlNzA0LTFmOTQtNDA4Yi1iMTMzLWYxZGRhNzI3N2E3ZTAKBggqhkjOPQQDAgNIADBFAiEA6D8eadYijkuOVFyxCfcoWFpLDtL6SrizvRC1qt+SjnYCICqjTVpmspHVTIhG6yDbEezgX5MGe+B+azfy5JFl5f+B".decodeBase64Bytes())[0]
    )

    override fun addCertificate(cert: String) {
        kotlin.runCatching {
            val certs = extractCerts(cert.decodeBase64Bytes())
            trustAnchors.add(certs[0])
        }
    }

    override fun verifyChain(certs: List<X509Certificate>): Boolean {
        val newCerts = certs.toMutableList()
        val root = newCerts.lastOrNull() ?: return false
        // is it a trust anchor?
        if(!trustAnchors.any { it.originalCert.contentEquals(root.originalCert) }) {
            val newRoot = trustAnchors.firstOrNull { it.subject == root.issuer } ?: return false
            newCerts.add(newRoot)
        }
        // if it is the root certificate, the chain is valid (as we trust the root)
        if(newCerts.size == 1) {
            return true
        }
        return runCatching { uniffi.heidi_crypto_rust.verifyChain(newCerts) }.getOrNull() ?: false
    }

    override fun getRoot(certs: List<X509Certificate>): X509Certificate? {
        val root = certs.lastOrNull() ?: return null
        if(!trustAnchors.any { it.originalCert.contentEquals(root.originalCert) }) {
            val newRoot = trustAnchors.firstOrNull { it.subject == root.issuer } ?: return null
            return newRoot
        }
        return root
    }
}
