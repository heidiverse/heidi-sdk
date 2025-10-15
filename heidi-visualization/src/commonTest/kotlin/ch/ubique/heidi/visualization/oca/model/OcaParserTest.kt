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

package ch.ubique.heidi.visualization.oca.model

import ch.ubique.heidi.visualization.extensions.calculateSaids
import ch.ubique.heidi.visualization.extensions.verifyIntegrity
import ch.ubique.heidi.visualization.oca.model.content.AttributeType
import ch.ubique.heidi.visualization.oca.model.overlay.input.EntryCodeOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.input.EntryOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.presentation.AriesBrandingOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.presentation.ClusterOrderingOverlay
import ch.ubique.heidi.visualization.oca.model.overlay.semantic.*
import ch.ubique.heidi.visualization.test.readResourceAsString
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class OcaParserTest {

	private val json = Json {
		ignoreUnknownKeys = true
		encodeDefaults = true
	}

	@Test
	fun `Parse Capture Base Attribute Types`(): Unit = runBlocking {
		val jsonContent = readResourceAsString("files/oca/capture_base_attribute_types.json")
		val ocaBundle = json.decodeFromString<OcaBundleJson>(jsonContent)

		assertEquals(9, ocaBundle.captureBase.attributes.size)
		assertIs<AttributeType.Text>(ocaBundle.captureBase.attributes.getValue("text"))
		assertIs<AttributeType.Numeric>(ocaBundle.captureBase.attributes.getValue("numeric"))
		assertIs<AttributeType.Reference>(ocaBundle.captureBase.attributes.getValue("reference"))
		assertIs<AttributeType.Boolean>(ocaBundle.captureBase.attributes.getValue("boolean"))
		assertIs<AttributeType.Binary>(ocaBundle.captureBase.attributes.getValue("binary"))
		assertIs<AttributeType.DateTime>(ocaBundle.captureBase.attributes.getValue("datetime"))
		val array = assertIs<AttributeType.Array>(ocaBundle.captureBase.attributes.getValue("array"))
		assertIs<AttributeType.Text>(array.contentType)
		val nestedArray = assertIs<AttributeType.Array>(ocaBundle.captureBase.attributes.getValue("nestedArray"))
		val nestedNestedArray = assertIs<AttributeType.Array>(nestedArray.contentType)
		assertIs<AttributeType.Numeric>(nestedNestedArray.contentType)
	}

	/**
	 * Input JSON taken from: https://github.com/hyperledger/aries-rfcs/blob/231d90dbd62d79006bea3564ddf869940f07aae0/features/0755-oca-for-aries/OCA4AriesBundle.json
	 */
	@Test
	fun `Parse Aries OCA JSON Bundle`(): Unit = runBlocking {
		val jsonContent = readResourceAsString("files/oca/aries_bundle.json")
		val ocaBundles = json.decodeFromString<List<OcaBundleJson>>(jsonContent)

		assertEquals(1, ocaBundles.size)

		val ocaBundle = ocaBundles.single()
		assertEquals(11, ocaBundle.captureBase.attributes.size)
		assertIs<AttributeType.DateTime>(ocaBundle.captureBase.attributes.getValue("birthdate_dateint"))
		assertIs<AttributeType.Text>(ocaBundle.captureBase.attributes.getValue("country"))
		assertIs<AttributeType.Binary>(ocaBundle.captureBase.attributes.getValue("picture"))
		assertEquals(10, ocaBundle.captureBase.flaggedAttributes.size)

		assertEquals(13, ocaBundle.overlays.size)
		assertEquals(2, ocaBundle.overlays.count { it is MetaOverlay })
		assertEquals(2, ocaBundle.overlays.count { it is EntryOverlay })
		assertEquals(1, ocaBundle.overlays.count { it is EntryCodeOverlay })
		assertEquals(1, ocaBundle.overlays.count { it is StandardOverlay })
		assertEquals(1, ocaBundle.overlays.count { it is FormatOverlay })
		assertEquals(2, ocaBundle.overlays.count { it is InformationOverlay })
		assertEquals(2, ocaBundle.overlays.count { it is LabelOverlay })
		assertEquals(1, ocaBundle.overlays.count { it is CharacterEncodingOverlay })
		assertEquals(1, ocaBundle.overlays.count { it is AriesBrandingOverlay })
	}

	/**
	 * Input JSON taken from: https://github.com/e-id-admin/open-source-community/blob/64cd5d86103babcc4004c476877b5ae03623e698/tech-roadmap/rfcs/oca/spec.md#cluster-ordering-overlay
	 */
	@Test
	fun `Parse Swiss OCA Cluster Ordering JSON Bundle`(): Unit = runBlocking {
		val jsonContent = readResourceAsString("files/oca/swiss_oca_cluster_ordering.json")
		val ocaBundle = json.decodeFromString<OcaBundleJson>(jsonContent)

		assertEquals(7, ocaBundle.captureBase.attributes.size)
		assertIs<AttributeType.Text>(ocaBundle.captureBase.attributes.getValue("id"))
		assertIs<AttributeType.DateTime>(ocaBundle.captureBase.attributes.getValue("birthdate"))
		assertTrue { ocaBundle.captureBase.flaggedAttributes.isEmpty() }

		assertEquals(1, ocaBundle.overlays.size)

		val overlay = ocaBundle.overlays.single()
		assertIs<ClusterOrderingOverlay>(overlay)
		assertEquals(3, overlay.clusterLabels.size)
		assertEquals("Inhalt", overlay.clusterLabels.getValue("main"))
		assertEquals(1, overlay.clusterOrder.getValue("main"))
		assertEquals(2, overlay.attributeClusterOrder.getValue("main").getValue("name"))
	}

	@Test
	fun `Test canonicalization`() : Unit = runBlocking {
		val jsonContent =readResourceAsString("files/oca/swiss_oca_cluster_ordering.json")
		val ocaBundle = json.decodeFromString<OcaBundleJson>(jsonContent)
		val canVersion = canonicalize(ocaBundle.captureBase)
		println(canVersion)
		val hash = computeCesrEncodedDigest(ocaBundle.captureBase)
		assertEquals(hash, ocaBundle.captureBase.digest)
	}

	@Test
	fun `Test OCA-Bundle Integrity`() : Unit = runBlocking {
		val jsonContent = readResourceAsString("files/oca/integrity_test_IM07E8mTX1Vn9knn9_LlGJPCeOkcrF7gnXyJitSL7D1R.json")
		val ocaBundle = json.decodeFromString<OcaBundleJson>(jsonContent)
		assertEquals(ocaBundle.captureBase.digest, "IM07E8mTX1Vn9knn9_LlGJPCeOkcrF7gnXyJitSL7D1R")
		assertTrue(ocaBundle.verifyIntegrity())
	}
}