use super::traits::FileHandler;
use crate::util::error::{Error, Result};
use crate::util::options;
use crate::util::sign::{KeyType, SignType};
use async_trait::async_trait;
use efi_signer::{DigestAlgorithm, EfiImage};
use std::collections::HashMap;
use std::fs::read;
use std::io::Write;
use std::path::PathBuf;
use uuid::Uuid;
pub struct EfiFileHandler {}

impl EfiFileHandler {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl FileHandler for EfiFileHandler {
    fn validate_options(&self, sign_options: &mut HashMap<String, String>) -> Result<()> {
        if let Some(detach) = sign_options.get(options::DETACHED) {
            if detach == "true" {
                return Err(Error::InvalidArgumentError(
                    "EFI image not support detached signature, you may need remove the --detach argument".to_string(),
                ));
            }
        }

        if let Some(key_type) = sign_options.get(options::KEY_TYPE) {
            if key_type != KeyType::X509EE.to_string().as_str() {
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
        sign_options.insert(options::INCLUDE_PARENT_CERT.to_string(), "true".to_string());
        Ok(())
    }

    async fn split_data(
        &self,
        path: &PathBuf,
        _sign_options: &mut HashMap<String, String>,
        _key_attributes: &HashMap<String, String>,
    ) -> Result<Vec<Vec<u8>>> {
        let buf = read(path)?;
        let pe = EfiImage::parse(&buf)?;
        let digest = match pe.get_digest_algo()? {
            Some(algo) => pe.compute_digest(algo)?,
            None => pe.compute_digest(DigestAlgorithm::Sha256)?,
        };
        info!(
            "file {} digest {:x?}",
            path.as_path().display().to_string(),
            digest.as_slice()
        );
        Ok(vec![digest])
    }

    async fn assemble_data(
        &self,
        path: &PathBuf,
        data: Vec<Vec<u8>>,
        temp_dir: &PathBuf,
        _sign_options: &HashMap<String, String>,
        _key_attributes: &HashMap<String, String>,
    ) -> Result<(String, String)> {
        let temp_file = temp_dir.join(Uuid::new_v4().to_string());
        let buf = read(path)?;
        let pe = EfiImage::parse(&buf)?;

        let mut signatures: Vec<efi_signer::Signature> = Vec::new();

        for d in data.iter() {
            signatures.push(efi_signer::Signature::decode(d)?);
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

#[cfg(test)]
mod test {
    use super::*;
    use std::env;

    #[test]
    fn test_validate_options() {
        let mut options = HashMap::new();
        options.insert(options::DETACHED.to_string(), "true".to_string());
        let handler: EfiFileHandler = EfiFileHandler::new();
        let result = handler.validate_options(&options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            Error::InvalidArgumentError(
                "EFI image not support detached signature, you may need remove the --detach argument".to_string(),
            ).to_string()
        );

        options.remove(options::DETACHED);
        options.insert(options::KEY_TYPE.to_string(), KeyType::X509EE.to_string());
        options.insert(
            options::SIGN_TYPE.to_string(),
            SignType::Authenticode.to_string(),
        );
        let result = handler.validate_options(&options);
        assert!(result.is_ok());

        *options
            .get_mut(options::KEY_TYPE.to_string().as_str())
            .unwrap() = KeyType::Pgp.to_string();
        let result = handler.validate_options(&options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            Error::InvalidArgumentError("EFI image only support x509 key type".to_string())
                .to_string()
        );

        *options
            .get_mut(options::KEY_TYPE.to_string().as_str())
            .unwrap() = KeyType::X509EE.to_string();
        *options
            .get_mut(options::SIGN_TYPE.to_string().as_str())
            .unwrap() = SignType::PKCS7.to_string();
        let result = handler.validate_options(&options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            Error::InvalidArgumentError(
                "EFI image only support authenticode sign type".to_string()
            )
            .to_string()
        );
    }

    #[tokio::test]
    async fn test_assemble_data() {
        let current_dir = env::current_dir().expect("get current dir failed");
        let signature_buf = read(current_dir.join("test_assets").join("efi.sign")).unwrap();

        let handler = EfiFileHandler::new();
        let mut options = HashMap::new();
        options.insert(options::KEY_TYPE.to_string(), KeyType::X509EE.to_string());
        options.insert(
            options::SIGN_TYPE.to_string(),
            SignType::Authenticode.to_string(),
        );
        let path = PathBuf::from(current_dir.join("test_assets").join("shimx64.efi"));

        let temp_dir = env::temp_dir();
        let result = handler
            .assemble_data(
                &path,
                vec![signature_buf],
                &temp_dir,
                &options,
                &HashMap::new(),
            )
            .await;
        assert!(result.is_ok());
        let (temp_file, file_name) = result.expect("efi sign should work");
        assert_eq!(temp_file.starts_with(temp_dir.to_str().unwrap()), true);
        assert_eq!(file_name.ends_with("shimx64.efi"), true);
        assert_eq!(
            read(temp_file).unwrap(),
            read(current_dir.join("test_assets").join("shimx64.efi.signed")).unwrap()
        );
    }
}
