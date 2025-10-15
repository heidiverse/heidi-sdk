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

package ch.ubique.heidi.wallet.credentials.format.mdoc

import com.android.identity.cbor.Cbor
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

object MdocUtils {

	private const val KEY_ISSUER_AUTH = "issuerAuth"
	private const val KEY_DOC_TYPE = "docType"

	@OptIn(ExperimentalEncodingApi::class)
	fun getDocType(payload: String): String {
		val base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL)
		val mdoc = Cbor.decode(base64.decode(payload))
		return Cbor.decode(mdoc[KEY_ISSUER_AUTH].asArray[2].asBstr).asTaggedEncodedCbor[KEY_DOC_TYPE].asTstr
	}

}
