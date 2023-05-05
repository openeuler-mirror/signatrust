use super::traits::FileHandler;
use crate::util::options;
use crate::util::sign::{SignType, KeyType};
use crate::util::error::{Error, Result};
use async_trait::async_trait;
use efi_signer::{DigestAlgorithm, EfiImage};
use std::collections::HashMap;
use std::fs::read;
use std::path::PathBuf;
use uuid::Uuid;
use std::io::Write;
pub struct EfiFileHandler {}

impl EfiFileHandler {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl FileHandler for EfiFileHandler {
    fn validate_options(&self, sign_options: &HashMap<String, String>) -> Result<()> {
        if let Some(detach) = sign_options.get(options::DETACHED) {
            if detach == "true" {
                return Err(Error::InvalidArgumentError(
                    "EFI image not support detached signature, you may need remove the --detach argument".to_string(),
                ));
            }
        }

        if let Some(key_type) = sign_options.get(options::KEY_TYPE) {
            if key_type != KeyType::X509.to_string().as_str() {
                return Err(Error::InvalidArgumentError(
                    "EFI image only support x509 key type".to_string(),
                ));
            }
        }

        if let Some(sign_type) = sign_options.get(options::SIGN_TYPE) {
            if sign_type != SignType::Authenticode.to_string().as_str() {
                return Err(Error::InvalidArgumentError(
                    "EFI image only support authenticode sign type".to_string(),
                ));
            }
        }
        Ok(())
    }

    async fn split_data(
        &self,
        path: &PathBuf,
        _sign_options: &mut HashMap<String, String>,
    ) -> Result<Vec<Vec<u8>>> {
        let buf = read(path)?;
        let pe = EfiImage::parse(&buf)?;
        let digest = match pe.get_digest_algo()? {
            Some(algo) => pe.compute_digest(algo)?,
            None => pe.compute_digest(DigestAlgorithm::Sha256)?,
        };
        info!("file {} digest {:x?}", path.as_path().display().to_string(), digest.as_slice());
        Ok(vec![digest])
    }

    async fn assemble_data(
        &self,
        path: &PathBuf,
        data: Vec<Vec<u8>>,
        temp_dir: &PathBuf,
        _sign_options: &HashMap<String, String>,
    ) -> Result<(String, String)> {
        let temp_file = temp_dir.join(Uuid::new_v4().to_string());
        let buf = read(path)?;
        let pe = EfiImage::parse(&buf)?;

        let mut signatures :Vec<efi_signer::Signature> = Vec::new();

        for d in data.iter() {
            signatures.push(efi_signer::Signature::decode(&d)?);
        }
        let new_pe = pe.set_authenticode(signatures)?;

        let mut file = std::fs::File::create(&temp_file)?;
    
        file.write_all(&new_pe)?;

        Ok((
            temp_file.as_path().display().to_string(),
            path.display().to_string(),
        ))
    }
}
