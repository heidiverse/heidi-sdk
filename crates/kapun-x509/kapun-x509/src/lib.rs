pub mod crypto;
pub mod x509;
pub use x509_parser;
pub use x509_parser::der_parser;

#[derive(Clone, Copy, Debug)]
pub enum ParseError {
    FailedToParseX509,
}
#[derive(Clone, Copy, Debug)]
pub enum TrustError {
    NoRootFound,
}
#[derive(Debug, Clone, Copy)]
pub enum X509Error {
    X509ParseError(ParseError),
    X509TrustError(TrustError),
    EmptyChain,
}
pub fn extract_public_key<T: AsRef<[u8]>>(cert: T) -> Result<Vec<u8>, ParseError> {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert.as_ref()) else {
        return Err(ParseError::FailedToParseX509);
    };
    Ok(cert.subject_pki.raw.to_vec())
}
