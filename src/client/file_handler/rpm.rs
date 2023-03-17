/*
 * // Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 * //
 * // signatrust is licensed under Mulan PSL v2.
 * // You can use this software according to the terms and conditions of the Mulan
 * // PSL v2.
 * // You may obtain a copy of Mulan PSL v2 at:
 * //         http://license.coscl.org.cn/MulanPSL2
 * // THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * // KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * // NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * // See the Mulan PSL v2 for more details.
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
use crate::client::cmd::options;
use crate::client::sign_identity::KeyType;
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
            if key_type != KeyType::PGP.to_string().as_str() {
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
    async fn assemble_data(&self, path: &PathBuf, data: Vec<Vec<u8>>, temp_dir: &PathBuf, _sign_options: &HashMap<String, String>) -> Result<(String, String)> {
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
        Ok((temp_rpm.as_path().display().to_string(), format!("{}", path.display().to_string())))
    }
}

