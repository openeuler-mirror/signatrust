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

use std::collections::HashMap;
use std::path::PathBuf;
use super::traits::FileHandler;
use async_trait::async_trait;
use crate::util::error::Result;
use std::fs::File;
use std::io::{BufReader, Read};
use rpm::{Header, IndexSignatureTag, RPMPackage};

use super::sequential_cursor::SeqCursor;
use uuid::Uuid;
use sha1;
use crate::util::options;
use crate::util::sign::KeyType;
use crate::util::error::Error;

#[derive(Clone)]
pub struct RpmFileHandler {

}


impl RpmFileHandler {
    pub fn new() -> Self {
        Self {

        }
    }
}

//todo: figure our why is much slower when async read & write with tokio is enabled.
#[async_trait]
impl FileHandler for RpmFileHandler {

    fn validate_options(&self, sign_options: &HashMap<String, String>) -> Result<()> {
        if let Some(detached) = sign_options.get(options::DETACHED) {
            if detached == "true" {
                return Err(Error::InvalidArgumentError("rpm file only support inside signature".to_string()))
            }
        }
        if let Some(key_type) = sign_options.get(options::KEY_TYPE) {
            if key_type != KeyType::Pgp.to_string().as_str() {
                return Err(Error::InvalidArgumentError("rpm file only support pgp signature".to_string()))
            }
        }
        Ok(())
    }

    //rpm has two sections need to be signed
    //1. header
    //2. header and content
    async fn split_data(&self, path: &PathBuf, _sign_options: &mut HashMap<String, String>) -> Result<Vec<Vec<u8>>> {
        let file = File::open(path)?;
        let package = RPMPackage::parse(&mut BufReader::new(file))?;
        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        //collect head and head&payload arrays
        package.metadata.header.write(&mut header_bytes)?;
        let mut header_and_content = Vec::new();
        header_and_content.extend(header_bytes.clone());
        header_and_content.extend(package.content.clone());
        Ok(vec![header_bytes, header_and_content])

    }
    async fn assemble_data(
        &self,
        path: & PathBuf,
        data: Vec<Vec<u8>>,
        temp_dir: &PathBuf,
        _sign_options: &HashMap<String, String>,
    ) -> Result<(String, String)> {
        let temp_rpm = temp_dir.join(Uuid::new_v4().to_string());
        let file = File::open(path)?;
        let mut package = RPMPackage::parse(&mut BufReader::new(file))?;
        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        package.metadata.header.write(&mut header_bytes)?;
        //calculate md5 and sha1 digest
        let mut header_and_content_cursor =
            SeqCursor::new(&[header_bytes.as_slice(), package.content.as_slice()]);
        let digest_md5 = {
            use md5::Digest;
            let mut hasher = md5::Md5::default();
            {
                // avoid loading it into memory all at once
                // since the content could be multiple 100s of MBs
                let mut buf = [0u8; 256];
                while let Ok(n) = header_and_content_cursor.read(&mut buf[..]) {
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[0..n]);
                }
            }
            let hash_result = hasher.finalize();
            hash_result.to_vec()
        };
        let digest_sha1 = {
            use sha1::Digest;
            let mut hasher = sha1::Sha1::default();
            hasher.update(&header_bytes);
            let digest = hasher.finalize();
            hex::encode(digest)
        };
        package.metadata.signature = Header::<IndexSignatureTag>::new_signature_header(
            header_and_content_cursor
                .len()
                .try_into()
                .expect("headers + payload can't be larger than 4gb"),
            &digest_md5,
            digest_sha1,
            data[0].as_slice(),
            data[1].as_slice(),
        );
        //save data into temp file
        let mut output = File::create(temp_rpm.clone())?;
        package.write(&mut output)?;
        Ok((temp_rpm.as_path().display().to_string(), format!("{}", path.display())))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env;
    use std::fs;
    use std::io::Write;

    fn get_signed_rpm() -> Result<PathBuf> {
        let current_dir = env::current_dir().expect("get current dir failed");
        Ok(PathBuf::from(current_dir.join("test_assets").join("Imath-3.1.4-1.oe2303.x86_64.rpm")))
    }

    fn generate_invalid_rpm() -> Result<PathBuf> {
        let temp_file = env::temp_dir().join(Uuid::new_v4().to_string());
        let mut file = File::create(temp_file.clone())?;
        let content = vec![1,2,3,4];
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
        let result = handler.validate_options(&options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid argument: rpm file only support pgp signature"
        );

        options.insert(options::KEY_TYPE.to_string(), KeyType::Pgp.to_string());
        options.insert(options::DETACHED.to_string(), "true".to_string());
        let result = handler.validate_options(&options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid argument: rpm file only support inside signature"
        );

        options.insert(options::DETACHED.to_string(), "false".to_string());
        let result = handler.validate_options(&options);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_split_data_success() {
        let mut sign_options = HashMap::new();
        let file_handler = RpmFileHandler::new();
        let path = get_signed_rpm().expect("get signed rpm failed");
        let raw_content = file_handler.split_data(&path, &mut sign_options).await.expect("get raw content failed");
        assert_eq!(raw_content.len(), 2);
        assert_eq!(raw_content[0].len(), 4325);
        assert_eq!(raw_content[1].len(), 67757);
    }

    #[tokio::test]
    async fn test_split_data_failed() {
        let mut sign_options = HashMap::new();
        let file_handler = RpmFileHandler::new();
        let path = generate_invalid_rpm().expect("generate invalid rpm failed");
        let _raw_content = file_handler.split_data(&path, &mut sign_options).await.expect_err("split invalid rpm file would failed");
    }

    #[tokio::test]
    async fn test_assemble_data_success() {
        let mut sign_options = HashMap::new();
        let file_handler = RpmFileHandler::new();
        let path = generate_signed_rpm().expect("generate signed rpm failed");
        let fake_signature = vec![vec![1,2,3,4], vec![1,2,3,4]];
        let _raw_content = file_handler.assemble_data(&path, fake_signature, &env::temp_dir(), &mut sign_options).await.expect("assemble data failed");
    }

}



