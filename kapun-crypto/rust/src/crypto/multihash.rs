#[derive(Debug, Clone, uniffi::Error)]
pub enum MultiHashError {
    DecodeError(String),
}

impl std::fmt::Display for MultiHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultiHashError::DecodeError(e) => f.write_str(&format!("EdDsaError::DecodeError: {e}")),
        }
    }
}

#[derive(Debug, Clone, uniffi::Object)]
pub struct MultiHash {
    code: u64,
    hash: Vec<u8>,
}

#[uniffi::export]
impl MultiHash {
    #[uniffi::constructor]
    pub fn create(code: u64, hash: Vec<u8>) -> Result<Self, MultiHashError> {
        Ok(MultiHash { code, hash })
    }

    #[uniffi::constructor]
    pub fn from_base58btc(str: &str) -> Result<Self, MultiHashError> {
        let decoded = multibase::Base::Base58Btc
            .decode(str)
            .map_err(|e| MultiHashError::DecodeError(e.to_string()))?;
        Self::from_bytes(decoded)
    }

    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, MultiHashError> {
        let (code, remaining) = unsigned_varint::decode::u64(&bytes)
            .map_err(|e| MultiHashError::DecodeError(e.to_string()))?;
        let (size, remaining) = unsigned_varint::decode::u64(remaining)
            .map_err(|e| MultiHashError::DecodeError(e.to_string()))?;
        let hash = remaining
            .get(..size as usize)
            .ok_or_else(|| MultiHashError::DecodeError("Invalid hash size".to_string()))?
            .to_vec();
        Ok(MultiHash { code, hash })
    }

    pub fn code(&self) -> u64 {
        self.code
    }

    pub fn hash(&self) -> Vec<u8> {
        self.hash.clone()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = unsigned_varint::encode::u64_buffer();
        let code_bytes = unsigned_varint::encode::u64(self.code, &mut bytes);
        let mut bytes = unsigned_varint::encode::u64_buffer();
        let size_bytes = unsigned_varint::encode::u64(self.hash.len() as u64, &mut bytes);
        [code_bytes, size_bytes, &self.hash].concat()
    }

    pub fn to_base58btc(&self) -> String {
        let bytes = self.to_bytes();
        multibase::Base::Base58Btc.encode(&bytes)
    }
}
