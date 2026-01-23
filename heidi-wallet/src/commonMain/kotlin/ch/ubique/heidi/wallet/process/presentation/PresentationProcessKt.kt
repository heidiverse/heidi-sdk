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

package ch.ubique.heidi.wallet.process.presentation

import ch.ubique.heidi.credentials.Mdoc
import ch.ubique.heidi.credentials.SdJwt
import ch.ubique.heidi.credentials.models.credential.CredentialType
import ch.ubique.heidi.credentials.models.metadata.KeyAssurance
import ch.ubique.heidi.credentials.Bbs
import ch.ubique.heidi.credentials.W3C
import ch.ubique.heidi.credentials.models.credential.CredentialMetadata
import ch.ubique.heidi.credentials.models.credential.CredentialModel
import ch.ubique.heidi.credentials.models.metadata.KeyMaterial
import ch.ubique.heidi.dcql.bbsCombinedClaimBasedProof
import ch.ubique.heidi.dcql.getVpToken
import ch.ubique.heidi.presentation.model.DocumentDigest
import ch.ubique.heidi.presentation.model.OID4VPVersion
import ch.ubique.heidi.presentation.model.TransactionData
import ch.ubique.heidi.presentation.model.TransactionType
import ch.ubique.heidi.presentation.request.PresentationRequest
import ch.ubique.heidi.presentation.request.VersionedPresentationRequest
import ch.ubique.heidi.proximity.documents.DocumentRequest
import ch.ubique.heidi.util.extensions.*
import ch.ubique.heidi.util.log.Logger
import ch.ubique.heidi.wallet.credentials.metadata.toKeyAssurance
import ch.ubique.heidi.wallet.credentials.presentation.AuthorizationRequestDiagnostics
import ch.ubique.heidi.wallet.credentials.presentation.DcqlMismatchInfo
import ch.ubique.heidi.wallet.credentials.presentation.LoA
import ch.ubique.heidi.wallet.crypto.SigningProvider
import ch.ubique.heidi.wallet.extensions.decodeMetadata
import ch.ubique.heidi.wallet.process.legacy.presentation.PresentationWorkflow
import io.ktor.client.HttpClient
import io.ktor.client.plugins.ResponseException
import io.ktor.client.request.forms.submitForm
import io.ktor.client.statement.bodyAsText
import io.ktor.http.parameters
import io.ktor.util.toLowerCasePreservingASCIIRules
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import uniffi.heidi_credentials_rust.generateNonce
import uniffi.heidi_crypto_rust.sha256Rs
import uniffi.heidi_dcql_rust.Credential
import uniffi.heidi_dcql_rust.DcqlQuery
import uniffi.heidi_util_rust.Value
import ch.ubique.heidi.wallet.process.presentation.models.TransactionDataWrapper
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonNames
import uniffi.heidi_credentials_rust.SignatureCreator
import uniffi.heidi_credentials_rust.w3cCredentialAsJson
import uniffi.heidi_dcql_rust.CredentialSetOption
import uniffi.heidi_dcql_rust.selectCredentialsWithInfo
import uniffi.heidi_util_rust.encodeCbor
import uniffi.heidi_wallet_rust.*
import kotlin.collections.set
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.ExperimentalTime
import kotlin.time.Instant


@Serializable
data class AuthorizationRequest(
    @JsonNames("client_id")
    val clientId: String,
    @JsonNames("presentation_definition")
    val presentationDefinition: Value? = null,
    @JsonNames("presentation_definition_uri")
    val presentationDefinitionUri: Value? = null,
    @JsonNames("dcql_query")
    val dcqlQuery: DcqlQuery? = null,
    @JsonNames("transaction_data")
    val transactionData: TransactionDataWrapper? = null
) {
    companion object {
        @OptIn(ExperimentalEncodingApi::class)
        fun fromValue(value: Value): AuthorizationRequest? {
            val clientId = value["client_id"].asString() ?: ""
            val presentationDefinition = value["presentation_definition"]
            var dcqlQuery: DcqlQuery? = value["dcql_query"]
                .takeIf { it != Value.Null }?.let {
                    it.asString()?.let {
                        try {
                            json.decodeFromString(it)
                        } catch (ex: Exception) {
                            null
                        }
                    } ?: it.transform<DcqlQuery>()
                }
            val transactionDataWrapper = TransactionDataWrapper.fromValue(value)

            return AuthorizationRequest(
                clientId,
                presentationDefinition = if (presentationDefinition is Value.Null) {
                    null
                } else {
                    presentationDefinition
                },
                dcqlQuery = dcqlQuery,
                transactionData = transactionDataWrapper,
            )
        }
    }
}

/// TODO: make typealiases for the different usecases/usecaseoption

/// 1) usecase
//      2)  (UseCase) options --> wird gefiltert nur erste option Hier haben wir immer nur eins
//         3) Credential Types (Query)
//            4) Actual Credentials

typealias DocumentCandidates = List<VerifiableCredential>
typealias PresentableDocumentCandidates = List<PresentableCredential>
typealias PresentationUsecase = List<PresentableDocumentCandidates>


@OptIn(ExperimentalTime::class)
class PresentationProcessKt private constructor(
    private val client: HttpClient?,
    private val signingProvider: SigningProvider,
    val data: PresentationMetadata?,
    private val versionedAuthRequest: VersionedPresentationRequest? = data?.let {
        PresentationRequest.detectProtocolVersionAndParse(
            it.authorizationRequest
        )
    },
    val authRequest: PresentationRequest? = versionedAuthRequest?.request,
    private val stateData: MutableMap<String, Value> = mutableMapOf(),
    private val origin: String?,
    private var documentRequest: DocumentRequest? = null,
    private var sessionTranscript: Value? = null,
    private var dcqlMismatchInfo: DcqlMismatchInfo? = null,
    private var bbsPresentTwo: Boolean = false,
    private var useLegacyVpToken: Boolean = false,
) {
    companion object {
        suspend fun initialize(
            blob: String,
            client: HttpClient,
            signingProvider: SigningProvider,
            origin: String? = null,
            useLegacyVpToken: Boolean = false,
        ): PresentationProcessKt {
            val result = parsePresentationOffer(blob)
            return PresentationProcessKt(
                client,
                signingProvider,
                result,
                origin = origin,
                useLegacyVpToken = useLegacyVpToken
            )
        }

        fun initializeProximity(
            jwt: String,
            client: HttpClient,
            signingProvider: SigningProvider,
        ): PresentationProcessKt {
            return initializeProximity(jwt,client, signingProvider)
        }

        fun initializeMdl(
            signingProvider: SigningProvider,
        ): PresentationProcessKt {
            return PresentationProcessKt(client = null, signingProvider, data = null, origin = null)
        }
    }

    fun getClientId(): String {
        return authRequest!!.clientId
    }

    fun getAgentInfo(): AgentInfo {
        return this.data!!.agentInfo
    }

    fun getDraftVersion(): OID4VPVersion {
        return versionedAuthRequest!!.version
    }
    fun putDocumentRequest(documentRequest: DocumentRequest) {
        this.documentRequest = documentRequest
    }
    fun putSessionTranscript(sessionTranscript: Value) {
        this.sessionTranscript = sessionTranscript
    }

    // Returns the VP authorization request (as pretty-printed json)
    fun getAuthorizationRequestForDiagnostics(): AuthorizationRequestDiagnostics {
        return this.dcqlMismatchInfo?.let {
            AuthorizationRequestDiagnostics.Dcql(
                it,
            )
        } ?: run {
            val prettyJson = Json {
                prettyPrint = true
            }
            AuthorizationRequestDiagnostics.Generic(prettyJson.encodeToString(this.data!!.authorizationRequest))
        }
    }

    fun getMatchingCredentialsProximity(
        documentRequest: DocumentRequest,
        credentials: List<CredentialModel>,
        validAt: Instant?
    ): List<CredentialSelection> {
        if (documentRequest is DocumentRequest.Mdl) {
            val documentCandidates = mutableListOf<PresentableDocumentCandidates>()
            for (docType in documentRequest.documents) {
                var filteredForDoctype =
                    credentials.filter { it.credentialType == CredentialType.Mdoc }
                        .filter { it.docType == docType.documentType }
                filteredForDoctype = filteredForDoctype.filter {
                    val mdoc = Mdoc.parse(it.payload)
                    docType.requestedDocumentItems.all { dataElement ->
                        mdoc.mdoc.namespaceMap[dataElement.namespace][dataElement.elementIdentifier] != Value.Null
                    }
                }

                documentCandidates.add(
                    filteredForDoctype.map {
                        val mdoc = Mdoc.parse(it.payload)
                        val values = docType.requestedDocumentItems.associate {
                            val element = mdoc.mdoc.namespaceMap[it.namespace][it.elementIdentifier]
                            Pair("/${it.namespace}/${it.elementIdentifier}", element.asString()?: element.printableString())
                        }
                        PresentableCredential(
                            VerifiableCredential(
                                it.id,
                                it.identityId,
                                it.name,
                                json.encodeToString(it.metadata),
                                it.payload
                            ), "", values, ""
                        )
                    }
                )
            }
            return listOf(CredentialSelection.ProximityCredentialSelection(documentCandidates))
        } else {
            return emptyList()
        }
    }

    fun getMatchingCredentials(
        credentials: DocumentCandidates,
        validAt: Instant?
    ): List<CredentialSelection> {
        val presentationDefinition = authRequest!!.presentationDefinition
        val dcqlQuery = authRequest.dcqlQuery

        return if (presentationDefinition != null) {
            // first result... hack
            val results = getMatchingCredentialsWithDifPex(
                presentationDefinition,
                credentials,
                validAt
            ).flatten()
            val groups = mutableMapOf<String, MutableList<PresentableCredential>>()
            val inputDescriptors =
                presentationDefinition["input_descriptors"].asArray() ?: return emptyList()
            for (inputDescriptor in inputDescriptors) {
                val id = inputDescriptor["id"].asString() ?: continue
                val group = inputDescriptor["group"].asArray()
                if (group == null) {
                    val noneGroups = groups.getOrPut("<<NONE>>") { mutableListOf() }
                    noneGroups.addAll(results.filter { it.responseId == id })
                } else {
                    for (innerG in group) {
                        val g = groups.getOrPut(innerG.asString()!!) { mutableListOf() }
                        g.addAll(results.filter { it.responseId == id })
                    }
                }
            }
            val submissionRequirements = presentationDefinition["submission_requirements"].asArray()
            val resultsByResponseId = results.groupBy { it.responseId }
            val purpose = presentationDefinition["purpose"].asString()
            if (submissionRequirements == null) {
                val result = presentationDefinition["input_descriptors"].asArray()?.map {
                    it["id"].asString() ?: "NO-KEY"
                } ?: emptyList()
                return result.map {
                    val elements = resultsByResponseId[it] ?: emptyList()
                    CredentialSelection.PexCredentialSelection(purpose, listOf(elements))
                }
            }
            val sets = mutableMapOf<String, MutableList<List<PresentableCredential>>>()
            var counter = 0
            for (requirement in submissionRequirements) {
                val name = requirement["name"].asString() ?: "requirement$counter"
                val rule = requirement["rule"].asString() ?: continue
                val count = requirement["count"].asLong() ?: continue
                val from = requirement["from"].asString() ?: continue
                if (rule.toLowerCasePreservingASCIIRules() != "pick") {
                    continue
                }
                val set = mutableListOf<List<PresentableCredential>>()
                val credentialsInGroup = groups[from] ?: mutableListOf()
                val groupedByResponseId =
                    credentialsInGroup.groupBy { it.responseId }.map { it.value }
                // we use the "first option" which is the simplest one
                // pick 1: take first group
                // pick 2: take the first two groups
                // ...
                for (i in 0..<count.toInt()) {
                    set.add(groupedByResponseId.getOrNull(i) ?: listOf())
                }
                sets[name] = set
                counter += 1
            }
            sets.map {
                CredentialSelection.PexCredentialSelection(purpose, it.value)
            }
        } else if (dcqlQuery != null) {
            val identityMap = credentials.associate {
                val meta = CredentialMetadata.fromString(it.metadata)
                it.payload to Pair(it.identityId, meta?.credentialType ?: CredentialType.Unknown)
            }

            // TODO: We need to improve this after refactoring
            val tmpList = credentials.map {
                when (identityMap[it.payload]?.second) {
                    CredentialType.OpenBadge303 -> {
                        val fuck = W3C.OpenBadge303.parseSerialized(it.payload).originalString
                        fuck
                    }
                    else -> it.payload
                }
            }
            val result = selectCredentialsWithInfo(dcqlQuery, tmpList)

            // Prioritize ZKP proofs for claim-based credentials
            val setOptions = prioritizeBbsClaimBasedProofs(dcqlQuery, result.setOptions)

            this.dcqlMismatchInfo = DcqlMismatchInfo(
                query = dcqlQuery,
                mismatches = result.mismatches,
                identityMap = identityMap
            )

            var resultOptions = setOptions.map { option ->
                CredentialSelection.DcqlCredentialSelection(
                    dcqlQuery,
                    option.purpose,
                    CredentialSetOptionsKt(
                        setOptions = option.setOptions.map { setOptions ->
                            // We need to sort the result, as we report empty results
                            val orderedOptions = setOptions.sortedBy {
                                it.options.size
                            }.reversed()
                            orderedOptions.map { setOption ->
                                CredentialSetOptionsKt.SetOptionKt(
                                    queryId = setOption.id,
                                    credentialOptions = setOption.options.map {
                                        val c = credentials.firstOrNull { c ->
                                            when (it.credential) {
                                                is Credential.MdocCredential -> (it.credential as Credential.MdocCredential).v1.originalMdoc == c.payload
                                                is Credential.SdJwtCredential -> (it.credential as Credential.SdJwtCredential).v1.originalSdjwt == c.payload
                                                is Credential.BbsCredential -> (it.credential as Credential.BbsCredential).v1.originalBbs == c.payload
                                                is Credential.W3cCredential -> (it.credential as Credential.W3cCredential).v1.originalSdjwt == c.payload
                                                is Credential.OpenBadge303Credential -> {
                                                    val vc = runCatching { W3C.OpenBadge303.parseSerialized(c.payload) }
                                                        .getOrNull() ?: return@firstOrNull false
                                                    val a = (it.credential as Credential.OpenBadge303Credential).v1
                                                    val b = vc.asW3CCredential()
                                                    (it.credential as Credential.OpenBadge303Credential).v1 == vc.asW3CCredential()
                                                }
                                            }
                                        }
                                        if (c == null) {
                                            return emptyList()
                                        }
                                        val relevantQuery = dcqlQuery.credentials?.firstOrNull { it.id == setOption.id }
                                        // This should never happen
                                        if(relevantQuery == null) {
                                            return emptyList()
                                        }
                                        // filter credentials that don't have a keybinding
                                        if (c.decodeMetadata()?.keyMaterial == KeyMaterial.Local.ClaimBased && relevantQuery.requireCryptographicHolderBinding == true) {
                                            return emptyList()
                                        }
                                        CredentialSetOptionsKt.SetOptionKt.DisclosureKt(
                                            selectedCredential = it.credential,
                                            c
                                        )
                                    }
                                )
                            }
                        }
                    )
                )
            }
            if(dcqlQuery.credentialSets?.isNotEmpty() == true) {
                val difference = dcqlQuery.credentialSets!!.size - resultOptions.size
               if(difference > 0 ) {
                   resultOptions = resultOptions.toMutableList()
                   for(i in 0..<difference) {
                       resultOptions.add(CredentialSelection.DcqlCredentialSelection(
                           dcqlQuery,
                           null,
                           CredentialSetOptionsKt(setOptions = emptyList())
                       ))
                   }
               }
            }
            return resultOptions
        } else {
            emptyList()
        }
    }

    fun prioritizeBbsClaimBasedProofs(
        dcqlQuery: DcqlQuery,
        setOptions: List<CredentialSetOption>
    ): List<CredentialSetOption> {
        // We need to present exactly two credentials
        if (setOptions.size != 2) {
            return setOptions
        }

        val (first, second) = Pair(setOptions[0], setOptions[1])
        val (q1, q2) = Pair(dcqlQuery.credentials?.find { q ->
            first.setOptions.flatMap { ops -> ops.map { o -> o.id } }.contains(q.id)
                    && q.format == "bbs-termwise"
        }, dcqlQuery.credentials?.find { q ->
            second.setOptions.flatMap { ops -> ops.map { o -> o.id } }.contains(q.id)
                    && q.format == "bbs-termwise"
        })

        val overlappingClaims = q1?.claims?.filter { c1 ->
            q2?.claims?.find { c2 -> c1.path == c2.path } != null
        } ?: listOf()
        // They must have at least some overlapping claims
        if (overlappingClaims.isEmpty()) {
            return setOptions
        }

        val req = Pair(q1?.requireCryptographicHolderBinding, q2?.requireCryptographicHolderBinding)
        // Exactly one of the credentials must prove device binding
        if (req != Pair(true, false)
            && req != Pair(false, true)) {
            return setOptions
        }

        val firstBbs = first.setOptions.firstNotNullOf {
            it.find { o -> (o.options.any { opt -> opt.credential is Credential.BbsCredential }) }
        }
        val firstOptions = firstBbs.options.filter { it.credential is Credential.BbsCredential }
        val secondBbs = second.setOptions.firstNotNullOf {
            it.find { o -> (o.options.any { opt -> opt.credential is Credential.BbsCredential }) }
        }
        val secondOptions = secondBbs.options.filter { it.credential is Credential.BbsCredential }

        bbsPresentTwo = true

        return listOf(
            CredentialSetOption(first.purpose, listOf(listOf(firstBbs.copy(options = firstOptions)))),
            CredentialSetOption(second.purpose, listOf(listOf(secondBbs.copy(options = secondOptions))))
        )
    }

    fun putPin(credRepresentative: String, pin: String) {
        val d = this.stateData.getOrPut(credRepresentative) { Value.Object(mutableMapOf()) }
        val obj = d.asObject()?.toMutableMap() ?: return
        obj.put("pin", Value.String(pin))
        this.stateData.put(credRepresentative, Value.Object(obj))
    }

    fun putPassphrase(credRepresentative: String, pin: String) {
        val d = this.stateData.getOrPut(credRepresentative) { Value.Object(mutableMapOf()) }
        val obj = d.asObject()?.toMutableMap() ?: return
        obj.put("passphrase", Value.String(pin))
        this.stateData.put(credRepresentative, Value.Object(obj))
    }

    fun putFrost(credRepresentative: String, frostBlob: String) {
        val d = this.stateData.getOrPut(credRepresentative) { Value.Object(mutableMapOf()) }
        val obj = d.asObject()?.toMutableMap() ?: return
        obj.put("frostBlob", Value.String(frostBlob))
        this.stateData.put(credRepresentative, Value.Object(obj))
    }

    fun putVerifiableCredential(
        credRepresentative: String,
        verifiableCredential: VerifiableCredential
    ) {
        val vc = verifiableCredential.toValue()
        val d = this.stateData.getOrPut(credRepresentative) { Value.Object(mutableMapOf()) }
        val obj = d.asObject()?.toMutableMap() ?: return
        obj.put("credential", vc)
        this.stateData.put(credRepresentative, Value.Object(obj))
    }

    fun isDcql(): Boolean {
        return this.authRequest?.dcqlQuery != null
    }

    fun isQes(): Boolean {
        return getQesAuthorizationDocuments().isNotEmpty() || getQesCreationAcceptanceDocuments().isNotEmpty()
    }

    fun getQesAuthorizationDocuments(): List<DocumentDigest> {
        return when (authRequest?.transactionData) {
            is TransactionDataWrapper.UC5 -> {
                stateData.keys.mapNotNull {
                    (authRequest.transactionData as TransactionDataWrapper.UC5).value
                        ?.get(it)
                        ?.map { it.second }
                        ?.filter {
                            it.type == TransactionType.QES_AUTHORIZATION.serialName
                        }
                }.flatten().mapNotNull { it.documentDigests }.flatten()
            }

            is TransactionDataWrapper.OpenId4Vp -> {
                (authRequest.transactionData as TransactionDataWrapper.OpenId4Vp).value
                    ?.map { it.second }
                    ?.filter {
                        it.type == TransactionType.QES_AUTHORIZATION.serialName
                    }?.mapNotNull { it.documentDigests }?.flatten() ?: emptyList()
            }

            null -> emptyList()
        }
    }

    fun getQesCreationAcceptanceDocuments(): List<TransactionData> {
        return when (authRequest?.transactionData) {
            is TransactionDataWrapper.UC5 -> {
                stateData.keys.mapNotNull {
                    (authRequest.transactionData as TransactionDataWrapper.UC5).value
                        ?.get(it)
                        ?.map { it.second }
                        ?.filter {
                            it.type == TransactionType.QCERT_CREATION_ACCEPTANCE.serialName
                        }
                }.flatten()
            }

            is TransactionDataWrapper.OpenId4Vp -> {
                (authRequest.transactionData as TransactionDataWrapper.OpenId4Vp).value
                    ?.map { it.second }
                    ?.filter {
                        it.type == TransactionType.QCERT_CREATION_ACCEPTANCE.serialName
                    } ?: emptyList()
            }

            null -> emptyList()
        }
    }

    fun getUsedCredentials(): List<Value> {
        val creds = mutableListOf<Value>()
        for (rep in this.stateData) {
            val c = rep.value["credential"]
            val content = rep.value["verificationContent"]
            creds.add(Value.Object(mapOf("credential" to c, "content" to content)))
        }
        return creds
    }

    //TODO: change return type
    suspend fun presentCredentials(email: String?, forProximity: Boolean): PresentationWorkflow {
        Logger("Presentation").warn("----> start presentation")
        //TODO: Add proximity flow here
        var combinedVpToken = if (isDcql()) {
            Value.Object(mapOf())
        } else {
            Value.Array(mutableListOf())
        }
        val numberOfTokens = this.stateData.size
        val descriptorMap = mutableListOf<Value>()
        var counter = 0
        var mdocGeneratedNonce = generateNonce(32UL)
        if (this.data == null) {
            if (!forProximity) {
                return PresentationWorkflow.Error("need data for non proximity")
            }
            val mdocs = mutableListOf<Mdoc>()
            val signers = mutableListOf<SignatureCreator>()
            for (rep in this.stateData) {
                val passphrase = rep.value["passphrase"].asString()
                val pin = rep.value["pin"].asString()
                val frostBlob = rep.value["frostBlob"].asString()
                val c: VerifiableCredential = rep.value["credential"].transform()
                    ?: return PresentationWorkflow.Error(code = "Invalid verifiable credential")
                val credentialMetadata = c.decodeMetadata()
                    ?: return PresentationWorkflow.Error("Failed to decode credential metadata")
                val nativeSigner = signingProvider.getNativeSigner(
                    keyMaterial = credentialMetadata.keyMaterial,
                    pin = pin,
                    frostBlob = frostBlob,
                    passphrase = passphrase,
                    email = email
                ) ?: return PresentationWorkflow.Error("No access to secure hardware")
                class SignerB(val s: NativeSigner) : SignatureCreator {
                    override fun alg(): String {
                        return s.alg()
                    }

                    override fun sign(bytes: ByteArray): ByteArray {
                        return s.signBytes(bytes)
                    }

                }
                if (credentialMetadata.credentialType != CredentialType.Mdoc)
                {
                    return PresentationWorkflow.Error("Need mdoc for proximity")
                }
                signers.add(SignerB(nativeSigner))
                mdocs.add(Mdoc.parse(c.payload))
            }

            val token = Mdoc.mdlPresentation(documentRequest!!, sessionTranscript!!,signers, mdocs)
            return PresentationWorkflow.ProximitySuccess(token!!)
        } else {
            val state = this.data.authorizationRequest["state"].asString()
            val nonce = this.data.authorizationRequest["nonce"].asString()
                ?: return PresentationWorkflow.Error(code = "No nonce")
            val audience = this.data.authorizationRequest["client_id"].asString() ?: this.origin
            ?: return PresentationWorkflow.Error(code = "No client id")
            val responseUri = this.data.authorizationRequest["response_uri"].asString()
            val responseMode = this.data.authorizationRequest["response_mode"].asString()

            class Signer(val s: NativeSigner) : SignatureCreator {
                override fun alg(): String {
                    return s.alg()
                }

                override fun sign(bytes: ByteArray): ByteArray {
                    return s.signBytes(bytes)
                }

            }

            if (bbsPresentTwo && this.authRequest?.dcqlQuery != null) {
                val (rep1, rep2) = Pair(this.stateData.entries.elementAt(0), this.stateData.entries.elementAt(1))
                val (c1, c2) = Pair<VerifiableCredential, VerifiableCredential>(
                    rep1.value["credential"].transform()
                        ?: return PresentationWorkflow.Error(code = "Invalid verifiable credential"),
                    rep2.value["credential"].transform()
                        ?: return PresentationWorkflow.Error(code = "Invalid verifiable credential")
                )
                val query = authRequest.dcqlQuery
                val (cQuery1, cQuery2) = Pair(
                    query?.credentials?.first { it.id == rep1.key }
                        ?: return PresentationWorkflow.Error(code = "CredentialQuery not found"),
                    query.credentials?.first { it.id == rep2.key }
                        ?: return PresentationWorkflow.Error(code = "CredentialQuery not found")
                )

                // The "ID" credential is the one that required device binding
                val (id, other) = if (cQuery1.requireCryptographicHolderBinding == true) {
                    Pair(Triple(c1, cQuery1, rep1), Triple(c2, cQuery2, rep2))
                } else {
                    if (cQuery2.requireCryptographicHolderBinding != true)
                        return PresentationWorkflow.Error(code = "One credential query must require cryptographic holder binding")
                    Pair(Triple(c2, cQuery2, rep2), Triple(c1, cQuery1, rep1))
                }

                val cIdMeta = id.first.decodeMetadata()
                    ?: return PresentationWorkflow.Error("Failed to decode credential metadata")
                val pin = id.third.value["pin"].asString()
                val frostBlob = id.third.value["frostBlob"].asString()
                val passphrase = id.third.value["passphrase"].asString()

                val nativeSigner = signingProvider.getNativeSigner(
                    keyMaterial = cIdMeta.keyMaterial,
                    pin = pin,
                    frostBlob = frostBlob,
                    passphrase = passphrase,
                    email = email
                ) ?: return PresentationWorkflow.Error(code = "Couldn't retrieve native signer")

                val signer = Signer(nativeSigner)

                val publicKey = nativeSigner.publicKey()
                val message = nonce.encodeToByteArray()
                val signature = signer.sign(message)

                val vpToken = bbsCombinedClaimBasedProof(
                    vc1 = Bbs.parse(id.first.payload),
                    q1 = id.second,

                    deviceBindingPk = publicKey,
                    message = sha256Rs(message),
                    messageSignature = signature,
                    clientId = audience,
                    nonce = nonce,

                    vc2 = Bbs.parse(other.first.payload),
                    q2 = other.second,

                    issuerPk = "zUC711y7V85xqmn7UidKFf5kwC3RWjB9CTsqEWjk81Yqs1TQW73oSawsQxCU3mdziXmbyrEPs2GFkXqvojqYiWz9JyXHaMjh7bR3XYPJTXgU9FZHDEWMarUAWiRBYu5ZenGmvyn",
                    issuerId = "did:example:issuer0",
                    issuerKeyId = "did:example:issuer0#bls12_381-g2-pub001",
                )

                val theToken = vpToken.getOrElse {
                    return PresentationWorkflow.Error("Proof failed: ${it.message}")
                }
                val innerObject = combinedVpToken.asObject()?.toMutableMap()
                    ?: return PresentationWorkflow.Error("VP Token has wrong format")
                innerObject.put(rep1.key, Value.String(theToken))
                innerObject.put(rep2.key, Value.String(theToken))
                combinedVpToken = Value.Object(innerObject)
            } else {
                for (rep in this.stateData) {
                    val passphrase = rep.value["passphrase"].asString()
                    val pin = rep.value["pin"].asString()
                    val frostBlob = rep.value["frostBlob"].asString()
                    val c: VerifiableCredential = rep.value["credential"].transform()
                        ?: return PresentationWorkflow.Error(code = "Invalid verifiable credential")
                    if (this.authRequest?.dcqlQuery != null) {
                        val query = authRequest.dcqlQuery
                        val credentialQuery = query?.credentials?.first { it.id == rep.key } ?: continue
                        val credentialMetadata = c.decodeMetadata()
                            ?: return PresentationWorkflow.Error("Failed to decode credential metadata")

                        val transactionData =
                            authRequest.transactionData?.getForCredential(credentialQuery.id)
                                ?.map { it.first }

                        val nativeSigner = signingProvider.getNativeSigner(
                            keyMaterial = credentialMetadata.keyMaterial,
                            pin = pin,
                            frostBlob = frostBlob,
                            passphrase = passphrase,
                            email = email
                        )

                        val vpToken: Result<String?> = when (credentialMetadata.credentialType) {
                            CredentialType.SdJwt -> SdJwt.parse(c.payload).getVpToken(
                                credentialQuery,
                                audience,
                                transactionData,
                                authRequest.transactionData?.specVersion(),
                                nonce,
                                nativeSigner?.let { Signer(nativeSigner) }
                            )
                            CredentialType.Mdoc -> {
                                // Non standard workaround for Warsaw event
                                if (responseMode == "direct_post") {
                                    mdocGeneratedNonce = ""
                                }
                                val responseUriHash =
                                    sha256Rs(encodeCbor(listOf(responseUri, mdocGeneratedNonce).toCbor()))
                                val clientIdHash =
                                    sha256Rs(encodeCbor(listOf(audience, mdocGeneratedNonce).toCbor()))
                                val nativeSigner = nativeSigner ?: return PresentationWorkflow.Error("mDoc cannot be claim bound")
                                Mdoc.parse(c.payload).getVpToken(
                                    credentialQuery,
                                    clientIdHash,
                                    responseUriHash,
                                    nonce,
                                    Signer(nativeSigner)
                                )
                            }
                            CredentialType.BbsTermwise -> {
                                val signer = nativeSigner?.let { Signer(nativeSigner) }

                                val publicKey = nativeSigner?.publicKey()
                                val message = nonce.encodeToByteArray()
                                val signature = signer?.sign(message)

                                // TODO: Get issuer stuff from credential metadata
                                Logger("ZKP").warn("----> before proof")
                                Bbs.parse(c.payload).getVpToken(
                                    credentialQuery,
                                    issuerPk = "zUC711y7V85xqmn7UidKFf5kwC3RWjB9CTsqEWjk81Yqs1TQW73oSawsQxCU3mdziXmbyrEPs2GFkXqvojqYiWz9JyXHaMjh7bR3XYPJTXgU9FZHDEWMarUAWiRBYu5ZenGmvyn",
                                    issuerId = "did:example:issuer0",
                                    issuerKeyId = "did:example:issuer0#bls12_381-g2-pub001",
                                    deviceBindingPk = publicKey,
                                    message = sha256Rs(message),
                                    messageSignature = signature,
                                    clientId = audience,
                                    nonce = nonce,
                                )
                            }
                            CredentialType.W3C_VCDM -> W3C.parse(c.payload).getVpToken(
                                credentialQuery,
                                audience,
                                transactionData,
                                authRequest.transactionData?.specVersion(),
                                nonce,
                                nativeSigner?.let { Signer(nativeSigner) }
                            )
                            CredentialType.OpenBadge303 -> W3C.OpenBadge303
                                .parseSerialized(c.payload)
                                .asVerifiablePresentation()
                            CredentialType.Unknown -> Result.success(null)
                        }
                        Logger("ZKP").warn("----> after proof")
                        if (vpToken.isFailure) {
                            return PresentationWorkflow.Error("Invalid Credential Type")
                        }
                        val theToken = vpToken.getOrNull()
                            ?: return PresentationWorkflow.Error("Invalid Credential Type")
                        val innerObject = combinedVpToken.asObject()?.toMutableMap()
                            ?: return PresentationWorkflow.Error("VP Token has wrong format")

                        val tokenValue = if (useLegacyVpToken) {
                            // OpenID4VP Draft 24
                            Value.String(theToken)
                        } else {
                            // OpenID4VP 1.0
                            Value.Array(listOf(Value.String(theToken)))
                        }

                        innerObject.put(rep.key, tokenValue)
                        combinedVpToken = Value.Object(innerObject)
                    } else {
                        val presentableCredential: PresentableCredential =
                            rep.value["presentableCredential"].transform()
                                ?: return PresentationWorkflow.Error(
                                    "Not a presentable credential"
                                )
                        val credentialMetadata = c.decodeMetadata()
                            ?: return PresentationWorkflow.Error("Failed to decode credential metadata")
                        val secureSubject = signingProvider.getSecureSubject(
                            keyMaterial = credentialMetadata.keyMaterial,
                            frostBlob = frostBlob,
                            pin = pin,
                            passphrase = passphrase,
                            email = email
                        ) ?: return PresentationWorkflow.Error("No access to secure hardware")

                        val authRequestObject = this.data.authorizationRequest
                        // Non standard workaround for Warsaw event
                        if (responseMode == "direct_post") {
                            mdocGeneratedNonce = ""
                        }

                        val nativeSigner = signingProvider.getNativeSigner(
                            keyMaterial = credentialMetadata.keyMaterial,
                            pin = pin,
                            frostBlob = frostBlob,
                            passphrase = passphrase,
                            email = email
                        ) ?: return PresentationWorkflow.Error("No access to secure hardware")

                        val vp = if (credentialMetadata.credentialType == CredentialType.Mdoc) {
                            val responseUriHash =
                                sha256Rs(encodeCbor(listOf(responseUri, mdocGeneratedNonce).toCbor()))
                            val clientIdHash =
                                sha256Rs(encodeCbor(listOf(audience, mdocGeneratedNonce).toCbor()))
                            val vp2 = Mdoc.parse(c.payload).getVpToken(
                                presentableCredential.values,
                                clientIdHash,
                                responseUriHash,
                                nonce,
                                Signer(nativeSigner)
                            )
                            // Cast is needed as Kotlin compiler can't figure out the type
                            (vp2.getOrNull()
                                ?: PresentationWorkflow.Error("Could not generate token")) as String
                        } else {
                            val sdjwt = SdJwt.parse(presentableCredential.credential.payload)
                            val transactionData =
                                authRequest!!.transactionData?.getForCredential(presentableCredential.responseId)
                                    ?.map { it.first }
                            sdjwt.getVpToken(
                                authRequestObject,
                                presentableCredential.responseId,
                                audience,
                                transactionData,
                                authRequest.transactionData?.specVersion(),
                                nonce,
                                Signer(nativeSigner)
                            ).getOrThrow()
                        }


                        val format: Value = Json.decodeFromString(presentableCredential.descriptorMap)
                        if (numberOfTokens == 1) {
                            descriptorMap.add(
                                Value.Object(
                                    mapOf(
                                        "id" to Value.String(rep.key),
                                        "path" to Value.String("$"),
                                        "format" to format[0]["format"],
                                    )
                                )
                            )
                            combinedVpToken = Value.String(vp)
                        } else {
                            val entries = combinedVpToken.asArray()!!.toMutableList()
                            entries.add(Value.String(vp))
                            combinedVpToken = Value.Array(entries)
                            descriptorMap.add(
                                Value.Object(
                                    mapOf(
                                        "id" to Value.String(rep.key),
                                        "path" to Value.String("$[${counter}]"),
                                        "format" to format[0]["format"],
                                    )
                                )
                            )
                        }
                        counter += 1
                    }
                }
            }

            val submission = if (isDcql()) {
                Value.Null
            } else {
                Value.Object(
                    mapOf(
                        "definition_id" to this.authRequest!!.presentationDefinition!!["id"],
                        "id" to this.authRequest.presentationDefinition!!["id"],
                        "descriptor_map" to Value.Array(descriptorMap)
                    )
                )
            }
            val response = if (responseMode == "direct_post.jwt" || responseMode == "dc_api.jwt") {
                val metadata = this.data.authorizationRequest["client_metadata"]
//            val tokenValues = if(combinedVpToken is Value.String) { combinedVpToken.v1 } else { Json.encodeToString(combinedVpToken ) }
                Logger("Presentation").warn("----> start encryption")
                val encryptedToken = encryptSubmission(
                    combinedVpToken,
                    submission,
                    mdocGeneratedNonce,
                    nonce.encodeToByteArray(),
                    state,
                    metadata
                )
                Logger("Presentation").warn("----> end encryption")
                state?.let {
                    Value.Object(
                        mapOf(
                            "response" to Value.String(encryptedToken),
//                            "state" to Value.String(it)
                        )
                    )
                } ?: Value.Object(
                    mapOf(
                        "response" to Value.String(encryptedToken)
                    )
                )
            } else {
                Value.Object(
                    listOfNotNull(
                        "vp_token" to combinedVpToken,
                        if (isDcql()) null else "presentation_submission" to submission,
                        if (state != null) "state" to Value.String(state) else null
                    ).toMap()
                ) as Value
            }
            if (responseMode == "dc_api" || responseMode == "dc_api.jwt") {
                return PresentationWorkflow.DcApiSuccess(response)
            }
            if (responseUri == null) {
                return PresentationWorkflow.Error("no response uri")
            }
            try {
                Logger("Presentation").warn("----> start request")
                val result = client!!.submitForm(url = responseUri, formParameters = parameters {
                    for (entry in response.asObject() ?: emptyMap()) {
                        val innerValue = entry.value
                        when (innerValue) {
                            is Value.String -> append(entry.key, innerValue.v1)
                            else -> append(entry.key, Json.encodeToString(entry.value))
                        }

                    }
                })
                try {
                    Logger("Presentation").warn("----> end request")
                    val bodyText = result.bodyAsText()
                    val body = json.parseToJsonElement(bodyText)
                    val obj = body.jsonObject["redirect_uri"]?.jsonPrimitive?.contentOrNull
                    val presentationDuringIssuance =
                        body.jsonObject["presentation_during_issuance_session"]?.jsonPrimitive?.contentOrNull
                    Logger("Presentation").warn("----> finish presentation")
                    return PresentationWorkflow.Success("Success", obj, presentationDuringIssuance)
                } catch (ex: Exception) {
                    println("$ex")
                    return PresentationWorkflow.Success("Success")
                }
            } catch (response: ResponseException) {
                return PresentationWorkflow.Error(response.response.status.toString() + " " + response.response.bodyAsText())
            }
        }
    }

    fun putPresentableCredential(credRepresentative: String, credential: PresentableCredential) {
        val vc = credential.toValue()
        val d = this.stateData.getOrPut(credRepresentative) { Value.Object(mutableMapOf()) }
        val obj = d.asObject()!!.toMutableMap()
        obj.put("presentableCredential", vc)
        this.stateData.put(credRepresentative, Value.Object(obj))
    }

    fun putVerificationContent(credRepresentative: String, content: String) {
        val d = this.stateData.getOrPut(credRepresentative) { Value.Object(mutableMapOf()) }
        val obj = d.asObject()!!.toMutableMap()
        obj.put("verificationContent", Value.String(content))
        this.stateData.put(credRepresentative, Value.Object(obj))
    }
}

sealed interface CredentialSelection {
    fun flattenCredentials(): List<VerifiableCredential>
    fun filterForRequestedLoa(requestedLoA: LoA): CredentialSelection
    fun doesVerifiableCredentialMatchLoa(
        credential: VerifiableCredential,
        requestedLoA: LoA
    ): Boolean {
        val keyAssurance = credential.decodeMetadata()?.keyMaterial?.toKeyAssurance()
        return when (requestedLoA) {
            LoA.Low -> keyAssurance in listOf(
                KeyAssurance.SoftwareLow,
                KeyAssurance.HardwareMedium,
                KeyAssurance.CloudHigh,
                KeyAssurance.EmergencyHigh
            )

            LoA.Medium -> keyAssurance in listOf(
                KeyAssurance.HardwareMedium,
                KeyAssurance.CloudHigh,
                KeyAssurance.EmergencyHigh
            )

            LoA.High -> keyAssurance in listOf(
                KeyAssurance.EmergencyHigh,
                KeyAssurance.CloudHigh
            )
        }
    }

    data class ProximityCredentialSelection(val presentableCredentials: List<PresentableDocumentCandidates>) :
        CredentialSelection {
        override fun flattenCredentials(): List<VerifiableCredential> {
            return this.presentableCredentials.flatten().map {
                it.credential
            }
        }

        override fun filterForRequestedLoa(requestedLoA: LoA): CredentialSelection {
            return this
        }

    }

    data class PexCredentialSelection(
        val purpose: String?,
        val presentableCredentials: List<PresentableDocumentCandidates>
    ) :
        CredentialSelection {
        override fun filterForRequestedLoa(requestedLoA: LoA): CredentialSelection {
            val filteredValues = this.presentableCredentials.map {
                it.filter {
                    doesVerifiableCredentialMatchLoa(it.credential, requestedLoA)
                }
            }
            return PexCredentialSelection(purpose, filteredValues)
        }

        override fun flattenCredentials(): List<VerifiableCredential> {
            return this.presentableCredentials.flatten().map {
                it.credential
            }
        }
    }

    data class DcqlCredentialSelection(
        val dcqlQuery: DcqlQuery,
        val purpose: String?,
        val dcqlSetOptions: CredentialSetOptionsKt
    ) :
        CredentialSelection {
        override fun filterForRequestedLoa(requestedLoA: LoA): CredentialSelection {
            return DcqlCredentialSelection(dcqlQuery, this.purpose,
                this.dcqlSetOptions.copy(setOptions =
                this.dcqlSetOptions.setOptions.map {
                    it.map {
                        it.copy(credentialOptions = it.credentialOptions.filter {
                            doesVerifiableCredentialMatchLoa(
                                it.selectedVerifiableCredential,
                                requestedLoA
                            )
                        })
                    }
                }
                )
            )
        }

        override fun flattenCredentials(): List<VerifiableCredential> {
            return this.dcqlSetOptions.setOptions.flatten().map {
                it.credentialOptions
            }.flatten().map {
                it.selectedVerifiableCredential
            }
        }
    }
}

data class CredentialSetOptionsKt(val setOptions: List<List<SetOptionKt>>) {
    data class SetOptionKt(val queryId: String, val credentialOptions: List<DisclosureKt>) {
        data class DisclosureKt(
            val selectedCredential: uniffi.heidi_dcql_rust.Credential,
            val selectedVerifiableCredential: VerifiableCredential
        )
    }
}
