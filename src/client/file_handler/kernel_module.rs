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
use std::fs;
use std::io;
use std::path::PathBuf;
use std::str;

use bincode::{config, Decode, Encode};
use std::collections::HashMap;
use std::io::{Read, Seek, Write};
use std::os::raw::{c_uchar, c_uint};
use uuid::Uuid;

use crate::util::options;
use crate::util::sign::{SignType, KeyType};
use crate::util::error::Error;

const FILE_EXTENSION: &str = "p7s";
const PKEY_ID_PKCS7: c_uchar = 2;
const MAGIC_NUMBER: &str = "~Module signature appended~\n";
const MAGIC_NUMBER_SIZE: usize = 28;
const SIGNATURE_SIZE: usize = 40;

// Reference https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/scripts/sign-file.c
#[derive(Encode, Decode, PartialEq, Debug)]
struct ModuleSignature {
    algo: c_uchar,       /* Public-key crypto algorithm [0] */
    hash: c_uchar,       /* Digest algorithm [0] */
    id_type: c_uchar,    /* Key identifier type [PKEY_ID_PKCS7] */
    signer_len: c_uchar, /* Length of signer's name [0] */
    key_id_len: c_uchar, /* Length of key identifier [0] */
    _pad: [c_uchar; 3],
    sig_len: c_uint, /* Length of signature data */
}

impl ModuleSignature {
    fn new(length: c_uint) -> ModuleSignature {
        ModuleSignature {
            algo: 0,
            hash: 0,
            id_type: PKEY_ID_PKCS7,
            signer_len: 0,
            key_id_len: 0,
            _pad: [0, 0, 0],
            sig_len: length,
        }
    }
}

#[derive(Clone)]
pub struct KernelModuleFileHandler {}

impl KernelModuleFileHandler {
    pub fn new() -> Self {
        Self {}
    }

    pub fn generate_detached_signature(&self, module: &str, signature: &[u8]) -> Result<()> {
        let mut buffer = std::fs::File::create(module)?;
        buffer.write_all(signature)?;
        Ok(())
    }

    pub fn append_inline_signature(
        &self,
        module: &PathBuf,
        tempfile: &PathBuf,
        signature: &[u8],
    ) -> Result<()> {
        let mut signed = fs::File::create(tempfile)?;
        signed.write_all(&self.get_raw_content(module)?)?;
        signed.write_all(signature)?;
        let sig_struct = ModuleSignature::new(signature.len() as c_uint);
        signed.write_all(&bincode::encode_to_vec(
            &sig_struct,
            config::standard()
                .with_fixed_int_encoding()
                .with_big_endian(),
        )?)?;
        signed.write_all(MAGIC_NUMBER.as_bytes())?;
        Ok(())
    }

    pub fn get_raw_content(&self, path: &PathBuf) -> Result<Vec<u8>> {
        let raw_content = fs::read(path)?;
        let mut file = fs::File::open(path)?;
        if file.metadata()?.len() <= MAGIC_NUMBER_SIZE as u64 {
            return Ok(raw_content);
        }
        //identify magic string and end of the file
        file.seek(io::SeekFrom::End(-(MAGIC_NUMBER_SIZE as i64)))?;
        let mut signature_ending: [u8; MAGIC_NUMBER_SIZE] = [0; MAGIC_NUMBER_SIZE];
        let _ = file.read(&mut signature_ending)?;
        return match str::from_utf8(signature_ending.as_ref()) {
            Ok(ending) => {
                return if ending == MAGIC_NUMBER {
                    file.seek(io::SeekFrom::End(-(SIGNATURE_SIZE as i64)))?;
                    let mut signature_meta: [u8; SIGNATURE_SIZE - MAGIC_NUMBER_SIZE] = [0; SIGNATURE_SIZE - MAGIC_NUMBER_SIZE];
                    let _ = file.read(&mut signature_meta)?;
                    //decode kernel module signature struct
                    let signature: ModuleSignature = bincode::decode_from_slice(
                        &signature_meta,
                        config::standard()
                            .with_fixed_int_encoding()
                            .with_big_endian(),
                    )?
                    .0;
                    if raw_content.len() < SIGNATURE_SIZE + signature.sig_len as usize {
                        return Err(Error::SplitFileError(
                            "invalid kernel module signature size found".to_owned(),
                        ));
                    }
                    //read raw content
                    Ok(raw_content
                        [0..(raw_content.len() - SIGNATURE_SIZE - signature.sig_len as usize)]
                        .to_owned())
                } else {
                    Ok(raw_content)
                };
            }
            Err(_) => {
                //try to read whole content
                Ok(raw_content)
            }
        };
    }
}

#[async_trait]
impl FileHandler for KernelModuleFileHandler {
    fn validate_options(&self, sign_options: &HashMap<String, String>) -> Result<()> {
        if let Some(key_type) = sign_options.get(options::KEY_TYPE) {
            if key_type != KeyType::X509.to_string().as_str() {
                return Err(Error::InvalidArgumentError(
                    "kernel module file only support x509 signature".to_string(),
                ));
            }
        }

        if let Some(sign_type) = sign_options.get(options::SIGN_TYPE) {
            if sign_type != SignType::CMS.to_string().as_str() {
                return Err(Error::InvalidArgumentError(
                    "kernel module file only support cms sign type".to_string(),
                ));
            }
        }
        Ok(())
    }

    //NOTE: currently we don't support sign signed kernel module file
    async fn split_data(
        &self,
        path: &PathBuf,
        _sign_options: &mut HashMap<String, String>,
    ) -> Result<Vec<Vec<u8>>> {
        Ok(vec![self.get_raw_content(path)?])
    }

    /* when assemble checksum signature when only create another .asc file separately */
    async fn assemble_data(
        &self,
        path: &PathBuf,
        data: Vec<Vec<u8>>,
        temp_dir: &PathBuf,
        sign_options: &HashMap<String, String>,
    ) -> Result<(String, String)> {
        let temp_file = temp_dir.join(Uuid::new_v4().to_string());
        //convert bytes into string
        if let Some(detached) = sign_options.get("detached") {
            if detached == "true" {
                self.generate_detached_signature(&temp_file.display().to_string(), &data[0])?;
                return Ok((
                    temp_file.as_path().display().to_string(),
                    format!("{}.{}", path.display(), FILE_EXTENSION),
                ));
            }
        }
        self.append_inline_signature(path, &temp_file, &data[0])?;
        return Ok((
            temp_file.as_path().display().to_string(),
            path.display().to_string(),
        ));
    }
}
