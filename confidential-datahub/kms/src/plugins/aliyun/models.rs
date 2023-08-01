use reqwest::header::HeaderMap;

#[derive(Clone, Debug, Default)]
pub struct EncryptRequest {
    pub request_headers: HeaderMap,
    pub key_id: Option<String>,
    pub plaintext: Option<Vec<u8>>,
    pub algorithm: Option<String>,
    pub aad: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
    pub padding_mode: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct EncryptResponse {
    pub response_headers: HeaderMap,
    pub key_id: Option<String>,
    pub ciphertext_blob: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
    pub algorithm: Option<String>,
    pub padding_mode: Option<String>,
    pub response_id: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct DecryptRequest {
    pub request_headers: HeaderMap,
    pub key_id: Option<String>,
    pub ciphertext_blob: Option<Vec<u8>>,
    pub algorithm: Option<String>,
    pub aad: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
    pub padding_mode: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct DecryptResponse {
    pub response_headers: HeaderMap,
    pub key_id: Option<String>,
    pub plaintext: Option<Vec<u8>>,
    pub algorithm: Option<String>,
    pub padding_mode: Option<String>,
    pub request_id: Option<String>,
}
