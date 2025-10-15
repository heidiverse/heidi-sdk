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

package ch.ubique.heidi.visualization.oca.processing

import ch.ubique.heidi.visualization.layout.LayoutCardImage
import ch.ubique.heidi.visualization.layout.LayoutData
import ch.ubique.heidi.visualization.layout.LayoutSectionProperty
import ch.ubique.heidi.visualization.layout.LayoutType
import ch.ubique.heidi.visualization.oca.model.OcaBundleJson
import ch.ubique.heidi.visualization.oca.model.content.TextShade
import ch.ubique.heidi.visualization.test.readResourceAsString
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.LocalDate
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class OcaProcessorTest {

	private val json = Json {
		ignoreUnknownKeys = true
	}

	/**
	 * Data taken from:
	 * https://github.com/bcgov/aries-oca-bundles/blob/main/OCABundles/schema/bcgov-digital-trust/student-card/testdata.csv
	 * https://github.com/bcgov/aries-oca-bundles/blob/main/OCABundles/schema/bcgov-digital-trust/student-card/OCABundle.json
	 */
	@Test
	fun `Process BC Gov Student card example`(): Unit = runBlocking {
		val credential = readResourceAsString("files/oca/bcgov/student_card/data.json")
		val ocaBundle = readResourceAsString("files/oca/bcgov/student_card/oca.json").let { json.decodeFromString<OcaBundleJson>(it) }

		val processor = OcaProcessor(
			userLanguage = "en",
			payload = credential,
			ocaBundle = ocaBundle,
		)

		val layoutData = processor.process(LayoutType.CARD)

		val cardLayout = assertIs<LayoutData.Card>(layoutData)
		assertEquals("DEMO - Student Card", cardLayout.credentialName)
		assertEquals("Best BC College", cardLayout.issuerName)
		assertEquals("Smith", cardLayout.title)
		assertEquals("Alice", cardLayout.subtitle)
		assertEquals(TextShade.DARK, cardLayout.textColor)
		val cardBackground = assertIs<LayoutCardImage.Url>(cardLayout.backgroundImage)
		assertEquals("https://raw.githubusercontent.com/bcgov/aries-oca-bundles/main/OCABundles/schema/bcgov-digital-trust/student-card/best-bc-background-image.jpg", cardBackground.url)
	}

	/**
	 * Data taken from:
	 * https://oca.colossi.network/guide/applications/swiss-passport-example.html
	 */
	@Test
	fun `Process Swiss Passport detail list example`(): Unit = runBlocking {
		val credential = readResourceAsString("files/oca/colossi/swiss_passport/data.json")
		val ocaBundle = readResourceAsString("files/oca/colossi/swiss_passport/oca.json").let { json.decodeFromString<OcaBundleJson>(it) }

		val processor = OcaProcessor(
			userLanguage = "en",
			payload = credential,
			ocaBundle = ocaBundle,
		)

		val layoutData = processor.process(LayoutType.DETAIL_LIST)

		val detailLayout = assertIs<LayoutData.DetailList>(layoutData)
		assertEquals(3, detailLayout.sections.size)

		val personalSection = detailLayout.sections[0]
		assertEquals("Personal Information", personalSection.sectionTitle)
		assertEquals(5, personalSection.sectionContent.size)
		assertEquals(
			LayoutSectionProperty(
				value = AttributeValue.Text("John Citizen"),
				label = "Name",
				information = "The full name of the holder, as identified by the issuing State or organization. For additional details see Doc 9303-3."
			),
			personalSection.sectionContent[0]
		)
		assertEquals(
			LayoutSectionProperty(
				value = AttributeValue.Date(LocalDate(2000, 1, 28)),
				label = "Date of birth",
				information = "Holder’s date of birth as recorded by the issuing State or organization. If the date of birth is unknown, see Doc 9303-3 for guidance."
			),
			personalSection.sectionContent[1]
		)
		assertEquals(
			LayoutSectionProperty(
				value = AttributeValue.Text("Luzern LU"),
				label = "Place of birth",
				information = "Field optionally used for city and State of the holder’s birthplace. Refer to Doc 9303-3 for further details."
			),
			personalSection.sectionContent[2]
		)
		assertEquals(
			LayoutSectionProperty(
				value = AttributeValue.Text("CHE"),
				label = "Nationality",
				information = "For details see Doc 9303-3."
			),
			personalSection.sectionContent[3]
		)
		assertEquals(
			LayoutSectionProperty(
				value = AttributeValue.Text("Male"),
				label = "Sex",
				information = "Sex of the holder, to be specified by use of the single initial commonly used in the language of the State or organization where the document is issued and, if translation into English, French or Spanish is necessary, followed by an oblique and the capital letter F for female, M for male, or X for unspecified."
			),
			personalSection.sectionContent[4]
		)


		val documentSection = detailLayout.sections[1]
		assertEquals("Document Data", documentSection.sectionTitle)
		assertEquals(6, documentSection.sectionContent.size)

		val additionalSection = detailLayout.sections[2]
		assertEquals("Additional Data", additionalSection.sectionTitle)
		assertEquals(3, additionalSection.sectionContent.size)
		assertEquals(
			LayoutSectionProperty(
				value = AttributeValue.Text("170"),
				label = "Optional personal data elements",
				information = "Optional personal data elements e.g. personal identification number or fingerprint, at the discretion of the issuing State or organization. If a fingerprint is included in this field, it should be presented as a 1:1 representation of the original. If a date is included, it shall follow the form of presentation described in Doc 9303-3.",
			),
			additionalSection.sectionContent[2]
		)
	}

}