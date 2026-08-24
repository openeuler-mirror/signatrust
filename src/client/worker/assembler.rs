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

use crate::client::sign_identity::SignIdentity;
use std::collections::HashMap;

use crate::client::file_handler::traits::FileHandler;
use crate::client::worker::traits::SignHandler;
use crate::util::error::Error;
use async_trait::async_trait;
use std::fs::copy;
use std::path::{Path, PathBuf};

use std::fs;

pub struct Assembler {
    temp_dir: PathBuf,
    key_attributes: HashMap<String, String>,
}

impl Assembler {
    pub fn new(temp_dir: String, key_attributes: HashMap<String, String>) -> Self {
        Self {
            temp_dir: PathBuf::from(temp_dir),
            key_attributes,
        }
    }
}

#[async_trait]
impl SignHandler for Assembler {
    //file handler used to generate signed file in temp folder and assembler will move the signed file back
    async fn process(&mut self, handler: Box<dyn FileHandler>, item: SignIdentity) -> SignIdentity {
        let signatures: Vec<Vec<u8>> = (*item.signature).borrow().clone();
        let sign_options = item.sign_options.borrow().clone();
        match handler
            .assemble_data(
                &item.file_path,
                signatures,
                &self.temp_dir,
                &sign_options,
                &self.key_attributes,
            )
            .await
        {
            Ok(content) => {
                debug!(
                    "successfully assemble file {}",
                    item.file_path.as_path().display()
                );
                let temp_file = Path::new(&content.0);
                match copy(temp_file, Path::new(&content.1)) {
                    Ok(_) => {
                        debug!(
                            "successfully saved file {}",
                            item.file_path.as_path().display()
                        );
                    }
                    Err(err) => {
                        *item.error.borrow_mut() =
                            Err(Error::AssembleFileError(format!("{:?}", err)));
                    }
                }
                //remove temp file when finished
                let _ = fs::remove_file(temp_file);
            }
            Err(err) => {
                *item.error.borrow_mut() = Err(Error::AssembleFileError(format!("{:?}", err)));
            }
        }
        item
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::file_handler::traits::FileHandler;
    use crate::client::sign_identity::SignIdentity;
    use crate::util::error::Result as AppResult;
    use crate::util::sign::{FileType, KeyType};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::io::Write;
    use std::path::PathBuf;

    struct MockFileHandler {
        assemble_result: AppResult<(String, String)>,
    }

    #[async_trait]
    impl FileHandler for MockFileHandler {
        fn validate_options(&self, _sign_options: &mut HashMap<String, String>) -> AppResult<()> {
            Ok(())
        }

        async fn split_data(
            &self,
            _path: &PathBuf,
            _sign_options: &mut HashMap<String, String>,
            _key_attributes: &HashMap<String, String>,
        ) -> AppResult<Vec<Vec<u8>>> {
            Ok(vec![])
        }

        async fn assemble_data(
            &self,
            _path: &PathBuf,
            _data: Vec<Vec<u8>>,
            _temp_dir: &PathBuf,
            _sign_options: &HashMap<String, String>,
            _key_attributes: &HashMap<String, String>,
        ) -> AppResult<(String, String)> {
            self.assemble_result.clone()
        }
    }

    fn make_sign_identity_with_signature(sig: Vec<Vec<u8>>) -> SignIdentity {
        let identity = SignIdentity::new(
            FileType::Rpm,
            PathBuf::from("/tmp/test.rpm"),
            KeyType::Pgp,
            "my-key".to_string(),
            HashMap::new(),
        );
        *identity.signature.borrow_mut() = sig;
        identity
    }

    #[tokio::test]
    async fn test_assembler_error_on_assemble_failure() {
        let handler = Box::new(MockFileHandler {
            assemble_result: Err(crate::util::error::Error::AssembleFileError(
                "mock failure".to_string(),
            )),
        });
        let mut assembler = Assembler::new("/tmp/signatrust".to_string(), HashMap::new());
        let identity = make_sign_identity_with_signature(vec![vec![1, 2, 3]]);
        let result = assembler.process(handler, identity).await;
        assert!(result.error.borrow().is_err());
    }

    #[tokio::test]
    async fn test_assembler_success_with_temp_file() {
        // Create a real temp file for the handler to "assemble" to
        let temp_dir = std::env::temp_dir().join("signatrust_test");
        let _ = std::fs::create_dir_all(&temp_dir);
        let temp_file = temp_dir.join("test-signed.rpm");
        let target_file = temp_dir.join("test-final.rpm");

        // Write something to the temp file
        {
            let mut f = std::fs::File::create(&temp_file).unwrap();
            f.write_all(b"signed content").unwrap();
        }

        let handler = Box::new(MockFileHandler {
            assemble_result: Ok((
                temp_file.to_str().unwrap().to_string(),
                target_file.to_str().unwrap().to_string(),
            )),
        });
        let mut assembler = Assembler::new(temp_dir.to_str().unwrap().to_string(), HashMap::new());
        let identity = make_sign_identity_with_signature(vec![vec![1, 2, 3]]);
        let result = assembler.process(handler, identity).await;
        // Should succeed: temp file exists and can be copied
        assert!(result.error.borrow().is_ok());

        // Clean up
        let _ = std::fs::remove_file(&target_file);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
