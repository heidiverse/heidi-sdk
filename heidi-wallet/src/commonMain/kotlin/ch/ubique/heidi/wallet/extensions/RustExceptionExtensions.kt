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

package ch.ubique.heidi.wallet.extensions

import ch.ubique.heidi.wallet.process.legacy.ProcessWorkflow
import uniffi.heidi_wallet_rust.*

data class ErrorState(
    val message: String?,
    val code: String,
    val cause: Exception,
) {
    val messageOrCode: String
        get() = message ?: code
}

fun ApiException.asErrorState(): ErrorState {
    return when (this) {
        is ApiException.AgentParse -> this.asErrorState()
        is ApiException.Backend -> this.asErrorState()
        is ApiException.Backup -> this.asErrorState()
        is ApiException.Credential -> this.asErrorState()
        is ApiException.Frost -> this.asErrorState()
        is ApiException.Generic -> this.asErrorState()
        is ApiException.Signing -> this.asErrorState()
        is ApiException.Hsm -> this.asErrorState()
    }
}

fun ApiException.AgentParse.asErrorState(): ErrorState {
    return when (this.v1) {
        is AgentParseException.Verifier -> this.v1.asErrorState()

        is AgentParseException.Issuer -> this.v1.asErrorState()
    }
}

fun AgentParseException.Verifier.asErrorState(): ErrorState {
    val exception = ApiException.AgentParse(this)
    return when (this.v1) {
        is VerifierParseException.CertificateParseException -> ErrorState(
            message = this.v1.v1, code = "APE|V|CPE", cause = exception
        )

        is VerifierParseException.Generic -> ErrorState(
            message = this.v1.v1, code = "APE|V|GE", cause = exception
        )

        is VerifierParseException.HeaderInvalid -> ErrorState(
            message = this.v1.v1, code = "APE|V|HI", cause = exception
        )

        is VerifierParseException.TokenInvalid -> ErrorState(
            message = this.v1.v1, code = "APE|V|TI", cause = exception
        )
    }
}

fun AgentParseException.Issuer.asErrorState(): ErrorState {
    val exception = ApiException.AgentParse(this)
    return when (this.v1) {
        is IssuerParseException.Generic -> ErrorState(
            message = this.v1.v1, code = "APE|I|GE", cause = exception
        )

        is IssuerParseException.UrlInvalid -> ErrorState(
            message = this.v1.v1, code = "APE|I|UI", exception
        )
    }
}

fun ApiException.Backend.asErrorState(): ErrorState {
    val exception = ApiException.Backend(this.v1)
    return when (this.v1) {
        is BackendException.BackupApiException -> ErrorState(
            message = this.v1.v1.title + (this.v1.v1.detail?.let { ": $it" } ?: ""),
            code = "B|BU",
            exception
        )

        is BackendException.Network -> this.v1.v1.asErrorState()

        is BackendException.ParseException -> ErrorState(
            message = this.v1.v1, code = "B|PE", exception
        )

        is BackendException.TokenException -> ErrorState(
            message = this.v1.v1, code = "B|TE", exception
        )
    }
}

fun NetworkException.asErrorState(): ErrorState {
    val exception = ApiException.Backend(BackendException.Network(this))
    return when (this) {
        is NetworkException.Connect -> ErrorState(
            message = this.v1, code = "B|NE|CO", exception
        )

        is NetworkException.Parse -> ErrorState(
            message = this.v1, code = "B|NE|PA", exception
        )

        is NetworkException.Request -> ErrorState(
            message = this.v1, code = "B|NE|REQ", exception
        )

        is NetworkException.Response -> ErrorState(
            message = this.v1, code = "B|NE|RES", exception
        )

        is NetworkException.Timeout -> ErrorState(
            message = this.v1, code = "B|NE|TO", exception
        )
    }
}

fun ApiException.Backup.asErrorState(): ErrorState {
    val exception = ApiException.Backup(this.v1)
    return when (this.v1) {
        is BackupException.CreatingSharedSecretFailed -> ErrorState(
            message = this.v1.message, code = "BU|CSF", exception
        )

        is BackupException.DeriveKeyMaterialFailed -> ErrorState(
            message = this.v1.message, code = "BU|DKF", exception
        )

        is BackupException.EncryptionFailed -> ErrorState(
            message = this.v1.message, code = "BU|EF", exception
        )

        is BackupException.RestoreFailed -> ErrorState(
            message = this.v1.message, code = "BU|RF", exception
        )

        is BackupException.SerializationFailed -> ErrorState(
            message = this.v1.message, code = "BU|SF", exception
        )

        is BackupException.SplitFileFailed -> ErrorState(
            message = this.v1.message, code = "BU|SFF", exception
        )
    }
}

fun ApiException.Credential.asErrorState(): ErrorState {
    val exception = ApiException.Credential(this.v1)
    return when (this.v1) {
        is CredentialException.FormatException -> ErrorState(
            message = null, code = "CE|FE", cause = exception
        )

        is CredentialException.InvalidTransactionCode -> ErrorState(
            message = null,
            code = "CE|Invalid Transaction Code",
            cause = exception
        )

        is CredentialException.KeyMismatch -> ErrorState(
            message = null, code = "CE|KM", cause = exception
        )
    }
}

fun ApiException.Frost.asErrorState(): ErrorState {
    val exception = ApiException.Frost(this.v1)
    return when (this.v1) {
        is FrostException.AesFailed -> ErrorState(
            message = null, code = "F|AES", exception
        )

        is FrostException.BipFailed -> ErrorState(
            message = null, code = "F|BIP", exception
        )

        is FrostException.FrostInitializationFailed -> ErrorState(
            message = null, code = "F|I", exception
        )

        is FrostException.FrostSigningFailed -> ErrorState(
            message = null, code = "F|S", exception
        )

        is FrostException.InvalidPublicKey -> ErrorState(
            message = null, code = "F|IPK", exception
        )

        is FrostException.SignatureInvalid -> ErrorState(
            message = null, code = "F|SI", exception
        )

        is FrostException.TooFewSigners -> ErrorState(
            message = null, code = "F|TFS", exception
        )

        is FrostException.FrostHsm -> ErrorState(
            message = null, code = "F|HSM", exception
        )

        is FrostException.InvalidPassphrase -> ErrorState(
            message = null, code = "F|IP", exception
        )
    }
}

fun ApiException.Signing.asErrorState(): ErrorState {
    val exception = ApiException.Signing(this.v1)
    return when (this.v1) {
        is SigningException.FailedToSign -> ErrorState(
            message = null, code = "S|FTS", exception
        )

        is SigningException.InvalidSecret -> ErrorState(
            message = null, code = "S|IS", exception
        )
    }
}

fun ApiException.Generic.asErrorState(): ErrorState {
    return when (this.v1) {
        is GenericException.Inner -> ErrorState(
            message = this.v1.v1.message, code = "GE|IE", this
        )

        is GenericException.Network -> ErrorState(
            message = this.v1.body, code = "GE|NE", this
        )

        is GenericException.LockException -> ErrorState(
            message = null, code = "GE|LE", this
        )

        is GenericException.Parse -> ErrorState(
            message = "Potential Model mismatch: ${this.v1.reason}", code = "GE|PE", this.v1.error
        )
    }
}

fun ApiException.Hsm.asErrorState(): ErrorState {
    return when (this.v1) {
        is HsmException.AesKeyFailure -> ErrorState(
            message = null, code = "HS|AES", this
        )

        is HsmException.ExpandFailure -> ErrorState(
            message = null, code = "HS|EF", this
        )

        is HsmException.InvalidPin -> ErrorState(
            message = null, code = "HS|IP", this
        )

        is HsmException.InvalidResult -> ErrorState(
            message = null, code = "HS|IR", this
        )

        is HsmException.LockException -> ErrorState(
            message = null, code = "HS|LE", this
        )

        is HsmException.MacFailure -> ErrorState(
            message = null, code = "HS|MF", this
        )

        is HsmException.NoKey -> ErrorState(
            message = null, code = "HS|NK", this
        )

        is HsmException.NoNonce -> ErrorState(
            message = null, code = "HS|NN", this
        )

        is HsmException.PinAborted -> ErrorState(
            message = null, code = "HS|PA", this
        )

        is HsmException.RegisterException -> ErrorState(
            message = null, code = "HS|RE", this
        )

        is HsmException.UnknownException -> ErrorState(
            message = null, code = "HS|UE", this
        )

        is HsmException.BatchException -> ErrorState(
            message = null, code = "HS|BE", this
        )
    }
}
