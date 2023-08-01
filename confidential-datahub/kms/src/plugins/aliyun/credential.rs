use anyhow::*;
use serde_json::Value;
use std::fs;

use openssl::pkcs12::Pkcs12;
use openssl::sign::Signer;

#[derive(Clone, Debug)]
pub struct Credential {
    pub key_file_dir: String,
    pub client_key_id: String,
}

impl Credential {
    fn get_client_key(&self) -> Result<Value> {
        let file = format!(
            "{}/clientKey_{}.json",
            self.key_file_dir, self.client_key_id,
        );
        let load_file = fs::File::open(file)?;
        let json_data: Value = serde_json::from_reader(load_file)?;
        Ok(json_data)
    }

    pub fn get_access_key_id(&self) -> Result<String> {
        let json_data = self.get_client_key()?;
        let key_id = json_data["KeyId"]
            .as_str()
            .ok_or_else(|| anyhow!("no KeyId"))?
            .to_owned();
        Ok(key_id)
    }

    fn get_access_key_secret(&self) -> Result<String> {
        let json_data = self.get_client_key()?;
        let key_secret = json_data["PrivateKeyData"]
            .as_str()
            .ok_or_else(|| anyhow!("no PrivateKeyData"))?
            .to_owned();
        Ok(key_secret)
    }

    fn get_password(&self) -> Result<String> {
        let file = format!("{}/password_{}.json", self.key_file_dir, self.client_key_id,);
        let load_file = fs::File::open(file)?;
        let json_data: Value = serde_json::from_reader(load_file)?;
        let password = json_data["ClientKeyPassword"]
            .as_str()
            .ok_or_else(|| anyhow!("no ClientKeyPassword"))?
            .to_owned();
        Ok(password)
    }

    pub fn get_signature(&self, str_to_sign: &str) -> Result<String> {
        let access_key_secret = self.get_access_key_secret()?;
        let password = self.get_password()?;

        let private_key_der = base64::decode(access_key_secret.as_bytes())?;
        let pkcs12 = Pkcs12::from_der(&private_key_der)?;
        println!("load private_key success");
        let parsed = pkcs12.parse2(&password)?;
        let private_key = parsed.pkey.ok_or_else(|| anyhow!("no pkey"))?;
        println!("parse private_key success");

        let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &private_key)?;
        signer.update(str_to_sign.as_bytes())?;
        let signature = signer.sign_to_vec()?;

        // Ok(format!("TOKEN {}", base64::encode(signature)))
        Ok(format!("Bearer {}", base64::encode(signature)))
    }
}
