/* Copyright 2024 Ubique Innovation AG

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
package ch.ubique.heidi.sample.verifier.feature.network

import ch.ubique.heidi.sample.verifier.data.dto.VerificationDisclosureDto
import ch.ubique.heidi.sample.verifier.data.dto.VerificationRequestDto
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module

class VerifierRepository(private val verifierService: VerifierService) {

	companion object {
		val koinModule = module {
			singleOf(::VerifierRepository)
		}
	}

	suspend fun getVerificationRequest(proofTemplate: ProofTemplate, nonce: String): VerificationRequestDto {
		// TODO For now we just hardcode the body from here: https://bund.ubique.ch/bund
		val body = when (proofTemplate) {
			ProofTemplate.IDENTITY_CARD_CHECK -> """
				{"nonce":"$nonce","client_id":"demo.bundesministerium.de","name":"IC card check","redirect_uri":"https://bund.ubique.ch/bund?session_id=","purpose":"ID card, all attributes","input_descriptors":[{"id":"full_credential_for_sd-jwt","name":"All credentials descriptor for SD-JWT format","purpose":"To verify the disclosure of all attributes for the SD-JWT format","group":["A"],"format":["vc+sd-jwt"],"fields":[{"path":["${'$'}['issuing_country']"],"filter":{"const":"DE"},"name":"issuing_country","purpose":"API test","optional":false},{"path":["${'$'}['issuing_authority']"],"name":"issuing_authority","purpose":"API test","optional":false},{"path":["${'$'}['given_name']"],"name":"given_name","purpose":"API test","optional":false},{"path":["${'$'}['family_name']"],"name":"family_name","purpose":"API test","optional":false},{"path":["${'$'}['birth_family_name']"],"name":"birth_family_name","purpose":"API test","optional":false},{"path":["${'$'}['birthdate']"],"name":"birthdate","purpose":"API test","optional":false},{"path":["${'$'}['place_of_birth']['locality']"],"name":"place_of_birth.locality","purpose":"API test","optional":false},{"path":["${'$'}['address']['locality']"],"name":"locality","purpose":"API test","optional":false},{"path":["${'$'}['address']['postal_code']"],"name":"postal_code","purpose":"API test","optional":false},{"path":["${'$'}['address']['street_address']"],"name":"street_address","purpose":"API test","optional":false},{"path":["${'$'}['nationalities']"],"name":"nationalities","purpose":"API test","optional":false}]},{"id":"full_credential_for_mdoc","name":"All credentials descriptor for MSO MDOC format","purpose":"To verify the disclosure of all attributes for the MSO MDOC format","group":["A"],"format":["mso_mdoc"],"fields":[{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['issuing_country']"],"filter":{"const":"DE"},"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['issuing_authority']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['given_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['family_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['family_name_birth']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['birth_date']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['birth_place']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['resident_city']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['resident_postal_code']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['resident_street']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['nationality']"],"name":"sample input descriptor field","purpose":"API test","optional":false}]}],"submission_requirements":[{"name":"sample submission requirement","purpose":"We only need a submission for one of two formats","rule":"PICK","count":1,"from":"A"}]}
			""".trimIndent()
			ProofTemplate.AGE_OVER_16 -> """
				{"nonce":"yJoW6Hq6XH8iiqRW54nacQ==","client_id":"demo.bundesministerium.de","redirect_uri":"https://bund.ubique.ch/bund?session_id=","name":"Age check over 16","purpose":"ID card, age over 16","input_descriptors":[{"id":"ueber_16_for_sd-jwt","name":"Ü16 descriptor for SD-JWT format","purpose":"To verify the disclosure of the Ü16 attribute for the SD-JWT format","group":["A"],"format":["vc+sd-jwt"],"fields":[{"path":["${'$'}['given_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['family_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['age_equal_or_over']['16']"],"filter":{"type":"boolean"},"name":"sample input descriptor field","purpose":"API test","optional":false}]},{"id":"ueber_16_for_mdoc","name":"Ü16 descriptor for MSO MDOC format","purpose":"To verify the disclosure of the Ü16 attribute for the MSO MDOC format","group":["A"],"format":["mso_mdoc"],"fields":[{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['given_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['family_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['age_over_16']"],"filter":{"type":"boolean"},"name":"sample input descriptor field","purpose":"API test","optional":false}]}],"submission_requirements":[{"name":"sample submission requirement","purpose":"We only need a submission for one of two formats","rule":"PICK","count":1,"from":"A"}]}
			""".trimIndent()
			ProofTemplate.AGE_OVER_18 -> """
				{"nonce":"akrIJ+nP9XHI8Et/cJD6IQ==","client_id":"demo.bundesministerium.de","redirect_uri":"https://bund.ubique.ch/bund?session_id=","name":"Age check over 18","purpose":"ID card, age over 18","input_descriptors":[{"id":"ueber_18_for_sd-jwt","name":"Ü18 descriptor for SD-JWT format","purpose":"To verify the disclosure of the Ü18 attribute for the SD-JWT format","group":["A"],"format":["vc+sd-jwt"],"fields":[{"path":["${'$'}['given_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['family_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['age_equal_or_over']['18']"],"filter":{"type":"boolean"},"name":"sample input descriptor field","purpose":"API test","optional":false}]},{"id":"ueber_18_for_mdoc","name":"Ü18 descriptor for MSO MDOC format","purpose":"To verify the disclosure of the Ü18 attribute for the MSO MDOC format","group":["A"],"format":["mso_mdoc"],"fields":[{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['given_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['family_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['age_over_18']"],"filter":{"type":"boolean"},"name":"sample input descriptor field","purpose":"API test","optional":false}]}],"submission_requirements":[{"name":"sample submission requirement","purpose":"We only need a submission for one of two formats","rule":"PICK","count":1,"from":"A"}]}
			""".trimIndent()
			ProofTemplate.AGE_OVER_65 -> """
				{"nonce":"AqxKzUTT8aEJDz/TSwMZ6w==","client_id":"demo.bundesministerium.de","redirect_uri":"https://bund.ubique.ch/bund?session_id=","name":"Age check over 65","purpose":"ID card, age over 65","input_descriptors":[{"id":"ueber_65_for_sd-jwt","name":"Ü65 descriptor for SD-JWT format","purpose":"To verify the disclosure of the Ü65 attribute for the SD-JWT format","group":["A"],"format":["vc+sd-jwt"],"fields":[{"path":["${'$'}['given_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['family_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['age_equal_or_over']['65']"],"filter":{"type":"boolean"},"name":"sample input descriptor field","purpose":"API test","optional":false}]},{"id":"ueber_65_for_mdoc","name":"Ü65 descriptor for MSO MDOC format","purpose":"To verify the disclosure of the Ü65 attribute for the MSO MDOC format","group":["A"],"format":["mso_mdoc"],"fields":[{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['given_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['family_name']"],"name":"sample input descriptor field","purpose":"API test","optional":false},{"path":["${'$'}['eu.europa.ec.eudi.pid.1']['age_over_65']"],"filter":{"type":"boolean"},"name":"sample input descriptor field","purpose":"API test","optional":false}]}],"submission_requirements":[{"name":"sample submission requirement","purpose":"We only need a submission for one of two formats","rule":"PICK","count":1,"from":"A"}]}
			""".trimIndent()
		}
		return verifierService.getVerificationRequest(body)
	}

	suspend fun getPresentationDefinition(requestUri: String): String {
		return verifierService.getPresentationDefinition(requestUri)
	}

	suspend fun verifyDocuments(response: String) {
		return verifierService.verifyDocuments(response)
	}

	suspend fun getAuthorization(transactionId: String): VerificationDisclosureDto {
		return verifierService.getAuthorization(transactionId)
	}
}
