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

package ch.ubique.heidi.trust.framework.swiss

import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.issuance.jwt.JwtParser
import ch.ubique.heidi.issuance.metadata.data.CredentialConfiguration
import ch.ubique.heidi.presentation.request.PresentationRequest
import ch.ubique.heidi.trust.framework.swiss.dto.VerificationTrustStatementsDto
import ch.ubique.heidi.trust.framework.swiss.model.TrustData
import ch.ubique.heidi.trust.framework.swiss.model.TrustedIdentity
import ch.ubique.heidi.trust.framework.swiss.model.TrustedIdentityV2
import ch.ubique.heidi.trust.framework.swiss.model.TrustedIssuance
import ch.ubique.heidi.trust.framework.swiss.model.TrustedVerification
import ch.ubique.heidi.trust.framework.swiss.model.fromV2
import ch.ubique.heidi.util.extensions.asString
import ch.ubique.heidi.util.extensions.get
import ch.ubique.heidi.util.extensions.transform
import io.ktor.http.Url
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module
import uniffi.heidi_crypto_rust.parseEncodedJwtPayload
import uniffi.heidi_crypto_rust.validateJwtWithDidDocument

/**
 * Implements trust protocols based on the Swiss Trust Infrastructure proposal (https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/rfcs/trust-protocol/trust-protocol.md)
 */
internal class SwissTrustRepository(
	private val trustService: SwissTrustService,
	private val json: Json,
) {

	companion object {
		val koinModule = module {
			singleOf(::SwissTrustRepository)
		}
		val TRUST_JWT_BETA_CREDENTIAL_SERVICE = "eyJ0eXAiOiJKV1QiLCJraWQiOiJ6dUQzZGkwZzVudDUxZnpIekNkaVpaSzlOUGFyY3pDQ1J6MkhkVGFRYzZnIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJiY3MuYWRtaW4uY2gvYmNzLXdlYi9pc3N1ZXItYWdlbnQvb2lkNHZjaSIsInByZWZMYW5nIjoiZGUiLCJ2Y3QiOiJUcnVzdFN0YXRlbWVudElkZW50aXR5VjEiLCJlbnRpdHlOYW1lIjp7ImRlIjoiQmV0YSBDcmVkZW50aWFsIFNlcnZpY2UiLCJlbiI6IkJldGEgQ3JlZGVudGlhbCBTZXJ2aWNlIn0sImlzcyI6ImUtaWQtYWRtaW46aXNzdWVyIiwibG9nb1VyaSI6eyJkZSI6ImRhdGE6aW1hZ2UvcG5nO2Jhc2U2NCxpVkJPUncwS0dnb0FBQUFOU1VoRVVnQUFBR1FBQUFCa0NBWUFBQUJ3NHBWVUFBQUdEa2xFUVZSNDJ1MmRhNGhWVlJUSHQrWE1QV3RiV2Nob09lVmo1dHl6TmxsKzhJYVBtYm5uckJWUlZFUlFVRmFXNUtQVXpBZWtwcFFEQnFZWmxSWVU5RVZONkVOV1VCU1pSWWxZZ1Qya3BKUXNGQ0tEbEV3czB6TDc0QVE5Wjd6M3JIUFB1ZWV1UDZ6djYremZYWGZ0dGZmYWV4dWpVcWxVcW9wMDRRUW90SVZGenhFQmhqZlpnR2Q1QVMrRmdOZFl4K3ZBOFl2VzhTWkEzbWFSZDFqSE93RjVGeUR2QWNkN3dmRStRTjREeUx1czQ1MFdlUWM0ZXM4NmVoTWN2UVRJNjhIUmsxNUEzVGFnZXlDZ216ME1MeTlnSjVvaG93YzA1cUMzamgza0ZjUFFDNkxwZ05GS1FOcG9rVDZ4amc5YXh5ZFROYVFmTE5LbmdQUXlJSzJ5U0RNOGpOaTBkd3pPdzlEM0s3UjFCVkNNYmdHa1ZZRDBsblg4WGVxRFhyMGRBRWZ2QXRMakh0S2tacjk4c1RHbVg0Ykh2OVFFTHV6d0hDK3h5SzlsNGhlZmVFVHhJZXQ0a3hmd1VzL255UGgrSVZVRWhiYXdDRWh6TGRMcjRQaW4zQVBvd3dEcHFIVzBHUnpkMXhOQnlhdkpMNCt4anBmM0pNNlRhcjBCNHE4Z29FZkJwL0d5RkViUXVWNFFMVllJc2FMbmF5K2didU9YVzJMenNNalg2NkRLbUlmUm5iR0JRRUFUZFRDbEpnTFJ6TmhBdkNDOFF3ZFQ3SzlyWG53Z1NGTjFNS1dBUkFzRWNnak4wTUVVeWlGQnREZytrSUJuNldCS0pYVjZRQ0twejg3QU90UG5Ib1pUNGhnNDNwMStoUERTK0VCY2RHOEdpcXkzNDM4SGIwa2ZDSFhuSWtMeUEwUWdRcktRUTNJREJLTUhjekhMeWcwUXgwc0VDa09hcGtERXZtT2hCSkRKQ2tUb080Sm92c0FzSzd4VmdVZ0JvZG54Z1JUREd4U0kyTFIzV3Z5ZHdTQzZXb0dJVmVxVEJCWVhJMVlnUXQvaCtFYUphZTlsQ2tUR0NuNTRwVWd6Z3dJUitvNGlqNHUvcDk3ZU1WaUJ5Rmh6UUU2Z3kyRlVzd0tSTVRPOGZJRkk0OG1wbmlNRkVodkkwSklWQVpKMkcyZ2VnSUNqNDJLdFdXbHY3dVFpUXBDK0Z3UkM3eXVRMkRYSWJqa2dTQnVyY0dBTE9IcFl3anlrcVFKL3UzZEorUU5JVzZ0b0FYcEhFRWkwT3BXMS80ektDNmk3Q2lBYkJJSHdRZ1VTRjBpMFVzNEJwTnNVU0Z3Z1BFZk9BVWVrUUdJQ2tWaFlqTE9lcFVEK0FVVDBuTWpRa2xVZ01ZRzBoeGVKT21FZDdWY2cxUUVCcEtQR21ET2xnV3hXSU5WR0NIMHM3Z1FnUGFGQXFvMFFYcCtFRTlNVVNOVkFGc3BIaUUvakZVaDFRQXBCZUkyOEY5aDVOaUQ5cmtDcWlKQzJybUdKT0FLTzl5cVF5b0FBMHVIRUhMR09YbFVnbFFMaGJZazVBZ0hkcjBBcWpwQlZ5UUZ4WVVjRmw3TXNNMjJsZ1NJbWNaL1ZrTkVEcFB5eGpwZWZmZzZKcmt2d3R6R3FHWkIrMWgzRDAvYjdoQm5XZFY2aTRXcVIzbEFncC8xM3RUM3gvMCtMMFV3RlVzTmowSDBuOWdtdGxkUWpqUXlrMllXWDFtU1dBWTQrVUNCOTltRjlXY05wWHpSZGdmU1pQeGJWYmlMZVFtY0IwbUVGMGt1WDRzaHhRMnBiSENFOW8wRCtOenBlcUhtMTJuUC9vZ0w1NzdPRVY2U3loQUJJMnhYSXYzemRZOUs2MDdkV0ozVHJDWWpJU2RzWTZ0ZHpWYmdDNmJsOTFKaFNVNm9ybjdXNHRiUmVnSGdZVHNuRWNyUjEvRkdqQXptVk82aC9Kb0FVaW54dG93UHhndWoyVEczYUFOSXJqUW9Fa0xhYXJMMlc0STNzR0o3VXBmeFpCZ0tPZm0xdXAwc3l1YlVKU0lzYURvamt1UTk1bFpxczQ1Mk5BZ1FjNzh2OGMwbE5mbmtNT0Q0bS9PSEhlbzVtVjIzZzZMajA5cXlIRWRkRlZ3WWd6V3VBRjNhVzFWV3JUQ1U5WEhWNHFmNVdJMzI4SUhHMWpoMEV5Ti9rRU1oQjhjTTNOYXpnUzNsNm53b2NIYStidk5IYldoY2duOGpINndZMDJlUkJFRVR6NnorSjAwTW1Ud0xIajlVdkVGcHJzdjJRWkxXUndtdnFjRWIxbkRIbURKTlhnYU9uNmdqR2hsekQrSE9Yc1pyTGJGS3dkZlZYYThTcTVxTUZ0VzVKcmNDV20wWVVCRFJSZXQwcjV2clViOWJSM2FhUkJRRjFXVWZmWnFFQ0x6aSt5cWlNTVNQby9KU3Y0UHZRY3pSQ1FmeE4xQitRSDZsMVZlOGhQWjM2VytoWmx1ZHpWTW54NnhqRjN2NWtEdlRuVWY2NGN5elNzMG5Od3NEUjg2WjE3Q0FkNklxbnh0eHBIWDBtZVloRzVJVUN6UzA4eHpvK0VHTjM3MGN2aUJacnJwQlVXMmtnSUswQXgwY3FxQ3QrZ1lEWEdML2NvZ09ZV0g0cHR3RFNDb3Q4cUplbWlDT0EwV3FMblVOMXdHcWxVN2NUelFXa0wvN2FmUTVJaXhJL3JLL3FJL243MFFUUEVaazg3bG1vVkNxVlNxV3FYLzBCblNaYkZ4YWVIN2dBQUFBQVNVVk9SSzVDWUlJPSJ9LCJpYXQiOjE3NDUzOTA1NjZ9.3BSbrVqVI9Ka3UyvUZNzgL7XnDWl1MiPZRXe3H8ZCMN9aVHxCtol2CSBT5MLyw8OGmjYb38om_UsBghclfm_gA"
	}

	suspend fun getIssuanceTrustData(
		url: String,
		credentialConfigurationIds: List<String>,
		supportedCredentialConfigurations: Map<String, CredentialConfiguration>,
	): TrustData.Issuance? = withContext(Dispatchers.IO) {
		val baseUrl = runCatching { Url(url).host }.getOrDefault(url)

		val trustStatements = try {
			trustService.getIssuanceTrustStatements(url)
		} catch (e: Exception) {
			if(baseUrl == "bcs.admin.ch") {
				val trustedIdentityJson = parseEncodedJwtPayload(TRUST_JWT_BETA_CREDENTIAL_SERVICE)
					?: return@withContext null
				val trustedIdentity = json.decodeFromString<TrustedIdentity>(trustedIdentityJson)
				return@withContext TrustData.Issuance(
					baseUrl = "bcs.admin.ch/bcs-web/issuer-agent/oid4vci",
					identity = trustedIdentity,
					identityJwt = TRUST_JWT_BETA_CREDENTIAL_SERVICE,
					issuance = null,
					issuanceJwt = null,
					isTrusted = true,
					isVerified = true
				)
			}
			return@withContext null
		}

		val encodedIdentityTrustStatementJwt = trustStatements.identity
		val trustedIdentityJwt = JwtParser(encodedIdentityTrustStatementJwt)
		val trustedIdentity = trustedIdentityJwt.getPayload()?.let {
			json.decodeFromString<TrustedIdentity>(it)
		}

		val encodedIssuanceTrustStatementJwt = trustStatements.issuance
		val trustedIssuanceJwt = encodedIssuanceTrustStatementJwt?.let { JwtParser(it) }
		val trustedIssuance = trustedIssuanceJwt?.getPayload()?.let {
			json.decodeFromString<TrustedIssuance>(it)
		}

		//TODO (but not for showcase): isTrusted should only be true if it is still valid: trustedIdentity.exp > Clock.System.now().toEpochMilliseconds() && trustedVerification.exp > Clock.System.now().toEpochMilliseconds()
		val isTrusted = trustedIdentityJwt.isSignatureValid("JWT")

		// Match the credential configuration IDs from the credential offer with the ones in the credential issuer metadata and then check if their VCT or DocType matches the ones in the trust statement
		val isCredentialConfigurationAllowed = credentialConfigurationIds.any { credentialConfigurationId ->
			supportedCredentialConfigurations[credentialConfigurationId]
				?.let {
					when (it) {
						is CredentialConfiguration.Mdoc -> trustedIssuance?.schemaIds?.contains(it.doctype) ?: (trustedIssuance?.schemaId == it.doctype)
						is CredentialConfiguration.SdJwt -> trustedIssuance?.schemaIds?.contains(it.vct) ?: (trustedIssuance?.schemaId == it.vct)
						else -> it.format == "zkp_vc"
					}
				} ?: false
		}

		val isVerified = trustedIdentity != null
				&& trustedIssuance != null
				&& trustedIssuance.sub == trustedIdentity.sub
				&& trustedIssuanceJwt.isSignatureValid("JWT")
				&& isCredentialConfigurationAllowed

		return@withContext TrustData.Issuance(
			baseUrl = baseUrl,
			identity = trustedIdentity,
			identityJwt = encodedIdentityTrustStatementJwt,
			issuance = trustedIssuance,
			issuanceJwt = encodedIssuanceTrustStatementJwt,
			isTrusted = isTrusted,
			isVerified = isVerified
		)
	}

	suspend fun getVerificationTrustData(
		url: String,
		presentationRequest: PresentationRequest,
		originalRequest: String?
	): TrustData.Verification? = withContext(Dispatchers.IO) {
		val baseUrl = runCatching { Url(url).host }.getOrDefault(url)
		val trustStatements = kotlin.runCatching { trustService.getVerificationTrustStatements(url) }.getOrNull()
		if(trustStatements != null) {
			return@withContext getOldVerificationTrustData(baseUrl, trustStatements)
		} else {
			// check presentation request integrity
			val presentationDidDoc = trustService.getDidDocument(did = presentationRequest.clientId)
			if(presentationDidDoc == null) {
				return@withContext null
			}
			val isTrusted = originalRequest?.let { validateJwtWithDidDocument(originalRequest, presentationDidDoc, true) } ?: return@withContext null

			val trustedIdentityJwt = trustService.getTrustFromDid(presentationRequest.clientId).firstOrNull()
			val trustedIdentitySdJwt = trustedIdentityJwt?.let { SdJwt.parse(it) }

			val didDoc = trustedIdentitySdJwt?.let { trustService.getDidDocument(did = trustedIdentitySdJwt.innerJwt.claims["iss"].asString()!!) }
			val isVerified = didDoc?.let { validateJwtWithDidDocument(trustedIdentitySdJwt.innerJwt.originalJwt, didDoc, true) }
			val trustedIdentity : TrustedIdentityV2? = isVerified?.let {  trustedIdentitySdJwt.innerJwt.claims.transform<TrustedIdentityV2>() }
			return@withContext TrustData.Verification(
				baseUrl = baseUrl,
				identity = trustedIdentity?.let { TrustedIdentity.fromV2(it) } ,
				identityJwt = trustedIdentityJwt,
				verification = null,
				verificationJwt = null,
				isTrusted = isTrusted,
				isVerified = isVerified ?: false
			)
		}
	}

	 fun getOldVerificationTrustData(baseUrl: String, trustStatements: VerificationTrustStatementsDto) : TrustData.Verification? {
		val encodedIdentityTrustStatementJwt = trustStatements.identity
		val trustedIdentityJwt = JwtParser(encodedIdentityTrustStatementJwt)
		val trustedIdentity = trustedIdentityJwt.getPayload()?.let {
			json.decodeFromString<TrustedIdentity>(it)
		}

		val encodedVerificationTrustStatementJwt = trustStatements.verification
		val trustedVerificationJwt = encodedVerificationTrustStatementJwt?.let { JwtParser(it) }
		val trustedVerification = trustedVerificationJwt?.getPayload()?.let {
			json.decodeFromString<TrustedVerification>(it)
		}

		//TODO (but not for showcase): isTrusted should only be true if it is still valid: trustedIdentity.exp > Clock.System.now().toEpochMilliseconds() && trustedVerification.exp > Clock.System.now().toEpochMilliseconds()
		val isTrusted = trustedIdentityJwt.isSignatureValid("vc+sd-jwt")
		val isVerified = trustedVerification != null
				&& trustedIdentity != null
				&& trustedIdentity.sub == trustedVerification.sub
				&& trustedVerificationJwt.isSignatureValid("vc+sd-jwt")

		return TrustData.Verification(
			baseUrl = baseUrl,
			identity = trustedIdentity,
			identityJwt = encodedIdentityTrustStatementJwt,
			verification = trustedVerification,
			verificationJwt = encodedVerificationTrustStatementJwt,
			isTrusted = isTrusted,
			isVerified = isVerified
		)
	}

}
