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

//! This module collects all error Enums/Structs used throught the project. It aims to provide
//! one single Error interface exposed to the wallet applications, to allow for an easy error handling.
//!
//! To allow for idiomatic rust, we implement various [From] traits our error cases.

use core::fmt;
#[cfg(feature = "reqwest")]
use reqwest::header::HeaderMap;
use serde::Deserialize;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
/// API Error is the generic interface. Any error thrown from
/// an FFI-Boundary MUST be an [ApiError]
pub enum ApiError {
    /// [GenericError] allows return errors not explicitly attached to a certain process
    /// It also exposes the possiblity to rethrow [anyhow::Error], to have a neat interface
    /// during fast prototyping. Ideally in a production app there should be as few [GenericError]s as possible.
    Generic(GenericError),
    /// [SigningError] Errors occuring during signing procedure.
    Signing(SigningError),
    /// [AgentParseError] Errors occuring during parsing of information about agents. Currently,
    /// error handling is not ideal. We should provide more specific errors in the future
    AgentParse(AgentParseError),
    /// [BackupError] occuring during generation of backups, or restoring such.
    Backup(BackupError),
    /// [BackendError] will be thrown when there are issues with the Backup-API
    Backend(BackendError),
    /// [CredentialError] happen during the issuance and indicate problems with formats/encodings
    Credential(CredentialError),
    /// [FrostError]s are thrown when the interaction with the emergency fails
    Frost(FrostError),
    /// [HsmError] occur during the interaction with the HSM-Cloud Backend.
    Hsm(HsmError),
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum GenericError {
    Inner(InnerError),
    /// Generic network errors. We expose body, headers and status to give a hint to what happend
    Network {
        status: u16,
        body: String,
        headers: Vec<String>,
    },
    Parse {
        reason: String,
        error: InnerError,
    },
    LockError,
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum InnerError {
    /// We expose [anyhow::Error] in the [Display] implementation, indicating at least
    /// what failed. Ideally we should get rid of all those errors, and provide specific ones
    /// instead
    Anyhow(anyhow::Error),
}

impl Display for GenericError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenericError::Inner(e) => write!(f, "GE|{e}"),
            GenericError::Network {
                status,
                body,
                headers,
            } => write!(f, "NE: status={status}, body={body}, headers={headers:?}"),
            GenericError::Parse { reason, error } => {
                write!(f, "PE: {reason}, error={error}")
            }
            GenericError::LockError => write!(f, "GE|mutex poisoned"),
        }
    }
}

impl Display for InnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InnerError::Anyhow(e) => write!(f, "AH: {e}"),
        }
    }
}

impl std::error::Error for ApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Generic(e) => write!(f, "GE|{e}"),
            ApiError::Signing(se) => write!(f, "SE|{se}"),
            ApiError::AgentParse(ape) => write!(f, "APE|{ape}"),
            ApiError::Backup(be) => write!(f, "BAE|{be}"),
            ApiError::Backend(be) => write!(f, "BE|{be}"),
            ApiError::Credential(ce) => write!(f, "CE|{ce}"),
            ApiError::Frost(fe) => write!(f, "FE|{fe}"),
            ApiError::Hsm(hsme) => write!(f, "HSM|{hsme}"),
            // ApiError::MiddlewareError(me) => write!(f, "ME|{me}"),
        }
    }
}

#[cfg(feature = "reqwest")]
impl From<(u16, Option<String>, HeaderMap)> for ApiError {
    fn from(value: (u16, Option<String>, HeaderMap)) -> Self {
        let headers = value
            .2
            .iter()
            .map(|(key, value)| format!("{key}={value:?}"))
            .collect::<Vec<_>>();
        ApiError::Generic(GenericError::Network {
            status: value.0,
            body: value.1.unwrap_or_default(),
            headers,
        })
    }
}

#[cfg(feature = "reqwest")]
impl From<(reqwest::Response, Option<String>)> for ApiError {
    fn from(value: (reqwest::Response, Option<String>)) -> Self {
        let status = value.0.status().as_u16();
        let headers = value
            .0
            .headers()
            .iter()
            .map(|(key, value)| format!("{key}={value:?}"))
            .collect::<Vec<_>>();
        ApiError::Generic(GenericError::Network {
            status,
            body: value.1.unwrap_or_default(),
            headers,
        })
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(value: serde_json::Error) -> Self {
        Self::Generic(GenericError::Parse {
            reason: "Failed to parse JSON".to_string(),
            error: InnerError::Anyhow(anyhow::anyhow!(value)),
        })
    }
}

impl From<base64::DecodeError> for ApiError {
    fn from(value: base64::DecodeError) -> Self {
        Self::Generic(GenericError::Parse {
            reason: "Failed to base64 decode".to_string(),
            error: InnerError::Anyhow(anyhow::anyhow!(value)),
        })
    }
}

impl From<ciborium::value::Error> for ApiError {
    fn from(value: ciborium::value::Error) -> Self {
        Self::Generic(GenericError::Parse {
            reason: "Failed to parse cbor".to_string(),
            error: InnerError::Anyhow(anyhow::anyhow!(value)),
        })
    }
}

impl<T> From<ciborium::de::Error<T>> for ApiError
where
    T: core::fmt::Debug + Send + Sync + 'static,
{
    fn from(value: ciborium::de::Error<T>) -> Self {
        Self::Generic(GenericError::Parse {
            reason: "Failed to deserialize cbor".to_string(),
            error: InnerError::Anyhow(anyhow::anyhow!(value)),
        })
    }
}

impl<T> From<ciborium::ser::Error<T>> for ApiError
where
    T: core::fmt::Debug + Send + Sync + 'static,
{
    fn from(value: ciborium::ser::Error<T>) -> Self {
        Self::Generic(GenericError::Parse {
            reason: "Failed to serialize cbor".to_string(),
            error: InnerError::Anyhow(anyhow::anyhow!(value)),
        })
    }
}

impl From<chrono::ParseError> for ApiError {
    fn from(value: chrono::ParseError) -> Self {
        Self::Generic(GenericError::Parse {
            reason: "Failed to parse date".to_string(),
            error: InnerError::Anyhow(anyhow::anyhow!(value)),
        })
    }
}

impl From<std::num::TryFromIntError> for ApiError {
    fn from(value: std::num::TryFromIntError) -> Self {
        Self::Generic(GenericError::Parse {
            reason: "Failed to convert integer".to_string(),
            error: InnerError::Anyhow(anyhow::anyhow!(value)),
        })
    }
}

impl From<http::header::InvalidHeaderValue> for ApiError {
    fn from(value: http::header::InvalidHeaderValue) -> Self {
        Self::Generic(GenericError::Parse {
            reason: "Failed to parse header value".to_string(),
            error: InnerError::Anyhow(anyhow::anyhow!(value)),
        })
    }
}

impl From<serde_urlencoded::ser::Error> for ApiError {
    fn from(value: serde_urlencoded::ser::Error) -> Self {
        Self::Generic(GenericError::Parse {
            reason: "Failed to serialize URL parameters".to_string(),
            error: InnerError::Anyhow(anyhow::anyhow!(value)),
        })
    }
}

impl From<HsmError> for ApiError {
    fn from(value: HsmError) -> Self {
        ApiError::Hsm(value)
    }
}

impl From<GenericError> for ApiError {
    fn from(value: GenericError) -> Self {
        Self::Generic(value)
    }
}

impl<T> From<std::sync::PoisonError<T>> for ApiError {
    fn from(_value: std::sync::PoisonError<T>) -> Self {
        ApiError::Generic(GenericError::LockError)
    }
}

impl From<FrostError> for ApiError {
    fn from(value: FrostError) -> Self {
        match value {
            FrostError::InvalidPassphrase(_) => ApiError::Hsm(HsmError::InvalidPin),
            _ => Self::Frost(value),
        }
    }
}

impl From<CredentialError> for ApiError {
    fn from(value: CredentialError) -> Self {
        Self::Credential(value)
    }
}

impl From<BackendError> for ApiError {
    fn from(value: BackendError) -> Self {
        Self::Backend(value)
    }
}

impl From<BackupError> for ApiError {
    fn from(value: BackupError) -> Self {
        Self::Backup(value)
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self::Generic(GenericError::Inner(InnerError::Anyhow(e)))
    }
}
impl From<SigningError> for ApiError {
    fn from(value: SigningError) -> Self {
        Self::Signing(value)
    }
}
impl From<AgentParseError> for ApiError {
    fn from(value: AgentParseError) -> Self {
        Self::AgentParse(value)
    }
}

impl From<FrostHsmError> for ApiError {
    fn from(value: FrostHsmError) -> Self {
        Self::Frost(FrostError::FrostHsm(value))
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum SigningError {
    FailedToSign,
    InvalidSecret,
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:?}", self))
    }
}

impl std::error::Error for SigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum AgentParseError {
    Verifier(VerifierParseError),
    Issuer(IssuerParseError),
}
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum VerifierParseError {
    HeaderInvalid(String),
    TokenInvalid(String),
    CertificateParseError(String),
    Generic(String),
}
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum IssuerParseError {
    UrlInvalid(String),
    Generic(String),
}

impl Display for AgentParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for AgentParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "AgentParseError"
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
}

impl AgentParseError {
    pub fn generic_verifier_error<T>(error: &str) -> Result<T, AgentParseError> {
        Err(AgentParseError::Verifier(VerifierParseError::Generic(
            error.to_string(),
        )))
    }
    pub fn generic_issuer_error<T>(error: &str) -> Result<T, AgentParseError> {
        Err(AgentParseError::Issuer(IssuerParseError::Generic(
            error.to_string(),
        )))
    }
}

pub trait IssuerError<R> {
    fn generic_issuer_error(self, msg: &str) -> Result<R, AgentParseError>;
}

pub trait VerifierError<R> {
    fn verifier_error(self, verifier_error: VerifierParseError) -> Result<R, AgentParseError>;
    fn header_invalid(self, msg: &str) -> Result<R, AgentParseError>;
    fn generic_verifier_error(self, msg: &str) -> Result<R, AgentParseError>;
}

impl<R, E: Debug> IssuerError<R> for Result<R, E> {
    fn generic_issuer_error(self, msg: &str) -> Result<R, AgentParseError> {
        self.map_err(|e| {
            AgentParseError::Issuer(IssuerParseError::Generic(format!("{msg}: {:?}", e)))
        })
    }
}

impl<R, E: Debug> VerifierError<R> for Result<R, E> {
    fn verifier_error(self, verifier_error: VerifierParseError) -> Result<R, AgentParseError> {
        self.map_err(|_| AgentParseError::Verifier(verifier_error))
    }

    fn header_invalid(self, msg: &str) -> Result<R, AgentParseError> {
        self.map_err(|e| {
            AgentParseError::Verifier(VerifierParseError::HeaderInvalid(format!("{msg}: {:?}", e)))
        })
    }

    fn generic_verifier_error(self, msg: &str) -> Result<R, AgentParseError> {
        self.map_err(|e| {
            AgentParseError::Verifier(VerifierParseError::Generic(format!("{msg}: {:?}", e)))
        })
    }
}

impl<R> VerifierError<R> for Option<R> {
    fn verifier_error(self, verifier_error: VerifierParseError) -> Result<R, AgentParseError> {
        match self {
            Some(ok) => Ok(ok),
            None => Err(AgentParseError::Verifier(verifier_error)),
        }
    }

    fn header_invalid(self, msg: &str) -> Result<R, AgentParseError> {
        match self {
            Some(ok) => Ok(ok),
            None => Err(AgentParseError::Verifier(
                VerifierParseError::HeaderInvalid(msg.to_string()),
            )),
        }
    }

    fn generic_verifier_error(self, msg: &str) -> Result<R, AgentParseError> {
        match self {
            Some(ok) => Ok(ok),
            None => Err(AgentParseError::Verifier(VerifierParseError::Generic(
                msg.to_string(),
            ))),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum BackupError {
    CreatingSharedSecretFailed(anyhow::Error),
    DeriveKeyMaterialFailed(anyhow::Error),
    SplitFileFailed(anyhow::Error),
    SerializationFailed(anyhow::Error),
    EncryptionFailed(anyhow::Error),
    RestoreFailed(anyhow::Error),
}

impl Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupError::CreatingSharedSecretFailed(e) => {
                f.write_str(&format!("CreatingSharedSecretFailed: {e}"))
            }
            BackupError::DeriveKeyMaterialFailed(e) => {
                f.write_str(&format!("DeriveKeyMaterialFailed: {e}"))
            }
            BackupError::SplitFileFailed(e) => f.write_str(&format!("SplitFileFailed: {e}")),
            BackupError::SerializationFailed(e) => {
                f.write_str(&format!("SerializationFailed: {e}"))
            }
            BackupError::EncryptionFailed(e) => f.write_str(&format!("EncryptionFailed: {e}")),
            BackupError::RestoreFailed(e) => f.write_str(&format!("EncryptionFailed: {e}")),
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct BackupApiError {
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    status: u16,
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum BackendError {
    BackupApiError(BackupApiError),
    Network(NetworkError),
    ParseError(String),
    TokenError(String),
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum NetworkError {
    Connect(String),
    Request(String),
    Timeout(String),
    Response(String),
    Parse(String),
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkError::Connect(c) => write!(f, "Could not connect: {c}"),
            NetworkError::Response(r) => write!(f, "Request returned error: {r}"),
            NetworkError::Parse(p) => write!(f, "Response could not be parsed: {p}"),
            NetworkError::Request(r) => write!(f, "Request failed: {r}"),
            NetworkError::Timeout(t) => write!(f, "Request timed out: {t}"),
        }
    }
}

// Implement Display for CustomError
impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackendError::BackupApiError(api_error) => write!(
                f,
                "API Error: {} - {}",
                api_error.title,
                api_error.detail.clone().unwrap_or("No value".to_string())
            ),
            BackendError::Network(ne) => write!(f, "Network Error: {}", ne),
            BackendError::ParseError(err) => write!(f, "Parse Error: {}", err),
            BackendError::TokenError(err) => write!(f, "Token Exchange faield: {err}"),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum CredentialError {
    KeyMismatch,
    InvalidTransactionCode,
    FormatError,
}

impl Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:?}", self))
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum FrostError {
    TooFewSigners,
    SignatureInvalid,
    InvalidPublicKey,
    FrostInitializationFailed(anyhow::Error),
    FrostSigningFailed(anyhow::Error),
    BipFailed(anyhow::Error),
    AesFailed(anyhow::Error),
    FrostHsm(FrostHsmError),
    InvalidPassphrase(anyhow::Error),
}

impl Display for FrostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FrostErrror: {:?}", self)
    }
}
#[cfg(feature = "reqwest")]
impl From<reqwest_middleware::Error> for ApiError {
    fn from(value: reqwest_middleware::Error) -> Self {
        #[cfg(feature = "uniffi")]
        if value.is_connect() {
            ApiError::Backend(BackendError::Network(NetworkError::Connect(
                value.to_string(),
            )))
        } else if value.is_request() {
            ApiError::Backend(BackendError::Network(NetworkError::Request(
                value.to_string(),
            )))
        } else if value.is_status() {
            ApiError::Backend(BackendError::Network(NetworkError::Response(
                value.to_string(),
            )))
        } else if value.is_decode() || value.is_body() {
            ApiError::Backend(BackendError::Network(NetworkError::Parse(
                value.to_string(),
            )))
        } else {
            ApiError::Backend(BackendError::Network(NetworkError::Response(
                value.to_string(),
            )))
        }
        #[cfg(not(feature = "uniffi"))]
        ApiError::Backend(BackendError::Network(NetworkError::Response(
            value.to_string(),
        )))
    }
}
#[cfg(feature = "reqwest")]
impl From<reqwest::Error> for ApiError {
    fn from(value: reqwest::Error) -> Self {
        #[cfg(feature = "uniffi")]
        if value.is_connect() {
            ApiError::Backend(BackendError::Network(NetworkError::Connect(
                value.to_string(),
            )))
        } else if value.is_request() {
            ApiError::Backend(BackendError::Network(NetworkError::Request(
                value.to_string(),
            )))
        } else if value.is_status() {
            ApiError::Backend(BackendError::Network(NetworkError::Response(
                value.to_string(),
            )))
        } else if value.is_decode() || value.is_body() {
            ApiError::Backend(BackendError::Network(NetworkError::Parse(
                value.to_string(),
            )))
        } else {
            ApiError::Backend(BackendError::Network(NetworkError::Response(
                value.to_string(),
            )))
        }
        #[cfg(not(feature = "uniffi"))]
        ApiError::Backend(BackendError::Network(NetworkError::Response(
            value.to_string(),
        )))
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum HsmError {
    AesKeyFailure,
    MacFailure,
    ExpandFailure,
    UnknownError,
    PinAborted,
    NoNonce,
    NoKey,
    LockError,
    InvalidPin,
    InvalidResult(String),
    RegisterError(String),
    BatchError(String),
}
impl Display for HsmError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HsmError::AesKeyFailure => f.write_str("AES encryption failure"),
            HsmError::MacFailure => f.write_str("MAC application failure"),
            HsmError::ExpandFailure => f.write_str("Could not hash to field"),
            HsmError::UnknownError => f.write_str("Unknown Error"),
            HsmError::PinAborted => f.write_str("Pin aborted"),
            HsmError::NoNonce => f.write_str("Invalid Nonce"),
            HsmError::NoKey => f.write_str("Invalid Key"),
            HsmError::RegisterError(e) => f.write_str(&format!("Register failed: {e}")),
            HsmError::LockError => write!(f, "Mutex is poison"),
            HsmError::InvalidPin => write!(f, "Invalid Pin"),
            HsmError::InvalidResult(r) => write!(f, "Result is invalid: {r}"),
            HsmError::BatchError(b) => write!(f, "Batch error {b}"),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum FrostHsmError {
    CouldNotGetNonce(anyhow::Error),
    UnknownError,
}

impl Display for FrostHsmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{self:?}"))
    }
}

#[macro_export]
macro_rules! api_error {
    ($e:expr) => {
        $e.into()
    };
    ($e:expr, msg) => {
        let mut splits = e.split("|");
        splits.rev()
        let p = splits.pop();
        match p {

            _ => {
                ApiError::Anyhow(anyhow::anyhow!("GE: {msg}"))
            }
        }
    }
}
