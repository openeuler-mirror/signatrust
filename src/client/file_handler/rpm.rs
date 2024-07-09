/*
 *
 *  * // Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  * //
 *  * // signatrust is licensed under Mulan PSL v2.
 *  * // You can use this software according to the terms and conditions of the Mulan
 *  * // PSL v2.
 *  * // You may obtain a copy of Mulan PSL v2 at:
 *  * //         http://license.coscl.org.cn/MulanPSL2
 *  * // THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 *  * // KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 *  * // NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *  * // See the Mulan PSL v2 for more details.
 *
 */

use super::traits::FileHandler;
use crate::util::error::Result;
use async_trait::async_trait;
use rpm::{Digests, Header, IndexSignatureTag, IndexTag, Package};
use std::collections::HashMap;
use std::fs::File;
#[allow(unused_imports)]
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::str::FromStr;

use crate::domain::datakey::plugins::openpgp::OpenPGPKeyType;
use crate::util::error::Error;
use crate::util::options;
use crate::util::sign::KeyType;
use uuid::Uuid;

#[derive(Clone)]
pub struct RpmFileHandler {}

impl RpmFileHandler {
    pub fn new() -> Self {
        Self {}
    }
    //defaults to RSA
    fn get_key_type(&self, key_attributes: &HashMap<String, String>) -> OpenPGPKeyType {
        match key_attributes.get(options::KEY_TYPE) {
            Some(value) => match OpenPGPKeyType::from_str(value) {
                Ok(key_type) => key_type,
                Err(_) => OpenPGPKeyType::Rsa,
            },
            None => OpenPGPKeyType::Rsa,
        }
    }

    fn generate_v3_signature(
        &self,
        sign_options: &HashMap<String, String>,
        package: &Package,
    ) -> bool {
        if let Some(v3_format) = sign_options.get(options::RPM_V3_SIGNATURE) {
            if v3_format == "true" {
                return true;
            }
        }
        if package
            .metadata
            .header
            .entry_is_present(IndexTag::RPMTAG_PAYLOADDIGEST)
            || package
                .metadata
                .header
                .entry_is_present(IndexTag::RPMTAG_PAYLOADDIGESTALT)
        {
            return false;
        }
        true
    }
}

//todo: figure our why is much slower when async read & write with tokio is enabled.
#[async_trait]
impl FileHandler for RpmFileHandler {
    fn validate_options(&self, sign_options: &mut HashMap<String, String>) -> Result<()> {
        if let Some(detached) = sign_options.get(options::DETACHED) {
            if detached == "true" {
                return Err(Error::InvalidArgumentError(
                    "rpm file only support inside signature".to_string(),
                ));
            }
        }
        if let Some(key_type) = sign_options.get(options::KEY_TYPE) {
            if key_type != KeyType::Pgp.to_string().as_str() {
                return Err(Error::InvalidArgumentError(
                    "rpm file only support pgp signature".to_string(),
                ));
            }
        }
        Ok(())
    }

    //rpm has two sections need to be signed for rpm v3 signature
    //1. header
    //2. header and content
    //while there is only section to be signed for rpm v4, also for eddsa key only v4 is supported
    //1. header
    async fn split_data(
        &self,
        path: &PathBuf,
        sign_options: &mut HashMap<String, String>,
        key_attributes: &HashMap<String, String>,
    ) -> Result<Vec<Vec<u8>>> {
        let file = File::open(path)?;
        let package = Package::parse(&mut BufReader::new(file))?;
        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        //collect head and head&payload arrays
        package.metadata.header.write(&mut header_bytes)?;
        return if self.get_key_type(key_attributes) == OpenPGPKeyType::Eddsa {
            if self.generate_v3_signature(sign_options, &package) {
                Err(Error::InvalidArgumentError(
                    "eddsa key does not support v3 signature".to_string(),
                ))
            } else {
                Ok(vec![header_bytes])
            }
        } else if self.generate_v3_signature(sign_options, &package) {
            let mut header_and_content = Vec::new();
            header_and_content.extend(header_bytes.clone());
            header_and_content.extend(package.content.clone());
            Ok(vec![header_bytes, header_and_content])
        } else {
            Ok(vec![header_bytes])
        };
    }
    async fn assemble_data(
        &self,
        path: &PathBuf,
        data: Vec<Vec<u8>>,
        temp_dir: &PathBuf,
        sign_options: &HashMap<String, String>,
        key_attributes: &HashMap<String, String>,
    ) -> Result<(String, String)> {
        let temp_rpm = temp_dir.join(Uuid::new_v4().to_string());
        let file = File::open(path)?;
        let mut package = Package::parse(&mut BufReader::new(file))?;
        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        package.metadata.header.write(&mut header_bytes)?;
        let Digests {
            header_digest_sha256,
            header_digest_sha1,
            header_and_content_digest,
        } = Package::create_sig_header_digests(
            header_bytes.as_slice(),
            package.content.as_slice(),
        )?;

        let key_type = self.get_key_type(key_attributes);
        let builder = match key_type {
            OpenPGPKeyType::Rsa => {
                if self.generate_v3_signature(sign_options, &package) {
                    Header::<IndexSignatureTag>::builder()
                        .add_digest(
                            &header_digest_sha1,
                            &header_digest_sha256,
                            &header_and_content_digest,
                        )
                        .add_rsa_signature_legacy(data[0].as_slice(), data[1].as_slice())
                } else {
                    Header::<IndexSignatureTag>::builder()
                        .add_digest(
                            &header_digest_sha1,
                            &header_digest_sha256,
                            &header_and_content_digest,
                        )
                        .add_rsa_signature(data[0].as_slice())
                }
            }
            OpenPGPKeyType::Eddsa => Header::<IndexSignatureTag>::builder()
                .add_digest(
                    &header_digest_sha1,
                    &header_digest_sha256,
                    &header_and_content_digest,
                )
                .add_eddsa_signature(data[0].as_slice()),
        };
        package.metadata.signature =
            builder.build(header_bytes.as_slice().len() + package.content.len());
        //save data into temp file
        let mut output = File::create(temp_rpm.clone())?;
        package.write(&mut output)?;
        Ok((
            temp_rpm.as_path().display().to_string(),
            format!("{}", path.display()),
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env;

    use std::io::Write;

    fn get_signed_rpm() -> Result<PathBuf> {
        let current_dir = env::current_dir().expect("get current dir failed");
        Ok(PathBuf::from(
            current_dir
                .join("test_assets")
                .join("Imath-3.1.4-1.oe2303.x86_64.rpm"),
        ))
    }

    fn get_signed_rpm_without_payload_digest() -> Result<PathBuf> {
        let current_dir = env::current_dir().expect("get current dir failed");
        Ok(PathBuf::from(
            current_dir
                .join("test_assets")
                .join("at-3.1.10-43.el6.x86_64.rpm"),
        ))
    }

    fn generate_invalid_rpm() -> Result<PathBuf> {
        let temp_file = env::temp_dir().join(Uuid::new_v4().to_string());
        let mut file = File::create(temp_file.clone())?;
        let content = vec![1, 2, 3, 4];
        file.write_all(&content)?;
        Ok(temp_file)
    }

    fn generate_signed_rpm() -> Result<PathBuf> {
        let original = get_signed_rpm()?;
        let mut src_file = File::open(original)?;
        let mut content = Vec::new();
        let _ = src_file.read_to_end(&mut content)?;
        let temp_file = env::temp_dir().join(Uuid::new_v4().to_string());
        let mut file = File::create(temp_file.clone())?;
        file.write_all(&content)?;
        Ok(temp_file)
    }

    #[test]
    fn test_validate_options() {
        let mut options = HashMap::new();
        options.insert(options::KEY_TYPE.to_string(), KeyType::X509EE.to_string());
        let handler = RpmFileHandler::new();
        let result = handler.validate_options(&mut options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid argument: rpm file only support pgp signature"
        );

        options.insert(options::KEY_TYPE.to_string(), KeyType::Pgp.to_string());
        options.insert(options::DETACHED.to_string(), "true".to_string());
        let result = handler.validate_options(&mut options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid argument: rpm file only support inside signature"
        );

        options.insert(options::DETACHED.to_string(), "false".to_string());
        let result = handler.validate_options(&mut options);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_split_rpm_with_payload_digest_success() {
        let mut sign_options = HashMap::new();
        let file_handler = RpmFileHandler::new();
        let path = get_signed_rpm().expect("get signed rpm failed");
        let raw_content = file_handler
            .split_data(&path, &mut sign_options, &HashMap::new())
            .await
            .expect("get raw content failed");
        assert_eq!(raw_content.len(), 1);
        assert_eq!(raw_content[0].len(), 4325);
    }

    #[tokio::test]
    async fn test_split_rpm_with_payload_digest_and_v3_force_success() {
        let mut sign_options = HashMap::new();
        sign_options.insert(options::RPM_V3_SIGNATURE.to_string(), true.to_string());
        let file_handler = RpmFileHandler::new();
        let path = get_signed_rpm().expect("get signed rpm failed");
        let raw_content = file_handler
            .split_data(&path, &mut sign_options, &HashMap::new())
            .await
            .expect("get raw content failed");
        assert_eq!(raw_content.len(), 2);
        assert_eq!(raw_content[0].len(), 4325);
        assert_eq!(raw_content[1].len(), 67757);
    }

    #[tokio::test]
    async fn test_split_rpm_with_payload_digest_and_v3_force_eddsa_failed() {
        let mut sign_options = HashMap::new();
        sign_options.insert(options::RPM_V3_SIGNATURE.to_string(), true.to_string());
        let mut key_attributes = HashMap::new();
        key_attributes.insert(
            options::KEY_TYPE.to_string(),
            OpenPGPKeyType::Eddsa.to_string(),
        );
        let file_handler = RpmFileHandler::new();
        let path = get_signed_rpm().expect("get signed rpm failed");
        file_handler
            .split_data(&path, &mut sign_options, &key_attributes)
            .await
            .expect_err("eddsa key does not support v3 signature");
    }

    #[tokio::test]
    async fn test_split_rpm_without_payload_digest_success() {
        let mut sign_options = HashMap::new();
        let file_handler = RpmFileHandler::new();
        let path = get_signed_rpm_without_payload_digest().expect("get signed rpm failed");
        let raw_content = file_handler
            .split_data(&path, &mut sign_options, &HashMap::new())
            .await
            .expect("get raw content failed");
        assert_eq!(raw_content.len(), 2);
        assert_eq!(raw_content[0].len(), 21484);
        assert_eq!(raw_content[1].len(), 60304);
    }

    #[tokio::test]
    async fn test_split_data_failed() {
        let mut sign_options = HashMap::new();
        let file_handler = RpmFileHandler::new();
        let path = generate_invalid_rpm().expect("generate invalid rpm failed");
        let _raw_content = file_handler
            .split_data(&path, &mut sign_options, &HashMap::new())
            .await
            .expect_err("split invalid rpm file would failed");
    }

    #[tokio::test]
    async fn test_assemble_data_success() {
        let mut sign_options = HashMap::new();
        let file_handler = RpmFileHandler::new();
        let path = generate_signed_rpm().expect("generate signed rpm failed");
        let fake_signature = vec![vec![1, 2, 3, 4], vec![1, 2, 3, 4]];
        let _raw_content = file_handler
            .assemble_data(
                &path,
                fake_signature,
                &env::temp_dir(),
                &mut sign_options,
                &HashMap::new(),
            )
            .await
            .expect("assemble data failed");
    }
}
