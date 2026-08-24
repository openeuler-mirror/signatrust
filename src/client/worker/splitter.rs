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

use crate::client::file_handler::traits::FileHandler;
use crate::client::worker::traits::SignHandler;
use crate::util::error;
use async_trait::async_trait;
use std::collections::HashMap;

pub struct Splitter {
    key_attributes: HashMap<String, String>,
}

impl Splitter {
    pub fn new(key_attributes: HashMap<String, String>) -> Self {
        Self { key_attributes }
    }
}

#[async_trait]
impl SignHandler for Splitter {
    async fn process(&mut self, handler: Box<dyn FileHandler>, item: SignIdentity) -> SignIdentity {
        let mut sign_options = item.sign_options.borrow().clone();
        match handler
            .split_data(&item.file_path, &mut sign_options, &self.key_attributes)
            .await
        {
            Ok(content) => {
                *item.raw_content.borrow_mut() = content;
                *item.sign_options.borrow_mut() = sign_options;
                debug!(
                    "successfully split file {} {:?}",
                    item.file_path.as_path().display(),
                    item.raw_content.as_ref()
                );
            }
            Err(err) => {
                *item.error.borrow_mut() = Err(error::Error::SplitFileError(format!("{:?}", err)))
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
    use std::path::PathBuf;

    struct MockFileHandler {
        split_result: AppResult<Vec<Vec<u8>>>,
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
            self.split_result.clone()
        }

        async fn assemble_data(
            &self,
            _path: &PathBuf,
            _data: Vec<Vec<u8>>,
            _temp_dir: &PathBuf,
            _sign_options: &HashMap<String, String>,
            _key_attributes: &HashMap<String, String>,
        ) -> AppResult<(String, String)> {
            Ok(("".to_string(), "".to_string()))
        }
    }

    fn make_sign_identity() -> SignIdentity {
        SignIdentity::new(
            FileType::Rpm,
            PathBuf::from("/tmp/test.rpm"),
            KeyType::Pgp,
            "my-key".to_string(),
            HashMap::new(),
        )
    }

    #[tokio::test]
    async fn test_splitter_success() {
        let handler = Box::new(MockFileHandler {
            split_result: Ok(vec![vec![1, 2, 3], vec![4, 5, 6]]),
        });
        let mut splitter =
            Splitter::new(HashMap::from([("algo".to_string(), "sha256".to_string())]));
        let identity = make_sign_identity();
        let result = splitter.process(handler, identity).await;
        assert!(result.error.borrow().is_ok());
        assert_eq!(
            *result.raw_content.borrow(),
            vec![vec![1, 2, 3], vec![4, 5, 6]]
        );
    }

    #[tokio::test]
    async fn test_splitter_error() {
        let handler = Box::new(MockFileHandler {
            split_result: Err(crate::util::error::Error::SplitFileError(
                "mock split failure".to_string(),
            )),
        });
        let mut splitter = Splitter::new(HashMap::new());
        let identity = make_sign_identity();
        let result = splitter.process(handler, identity).await;
        assert!(result.error.borrow().is_err());
    }

    #[tokio::test]
    async fn test_splitter_empty_content() {
        let handler = Box::new(MockFileHandler {
            split_result: Ok(vec![]),
        });
        let mut splitter = Splitter::new(HashMap::new());
        let identity = make_sign_identity();
        let result = splitter.process(handler, identity).await;
        assert!(result.error.borrow().is_ok());
        assert!(result.raw_content.borrow().is_empty());
    }
}
