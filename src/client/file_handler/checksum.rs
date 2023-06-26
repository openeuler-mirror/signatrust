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
use crate::util::sign::{KeyType};
use crate::util::error::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use tokio::fs;
use uuid::Uuid;

use crate::util::options;
use crate::util::error::Error;
use std::collections::HashMap;

const FILE_EXTENSION: &str = "asc";

#[derive(Clone)]
pub struct CheckSumFileHandler {}

impl CheckSumFileHandler {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl FileHandler for CheckSumFileHandler {
    fn validate_options(&self, sign_options: &HashMap<String, String>) -> Result<()> {
        if let Some(detached) = sign_options.get(options::DETACHED) {
            if detached == "false" {
                return Err(Error::InvalidArgumentError(
                    "checksum file only support detached signature".to_string(),
                ));
            }
        }

        if let Some(key_type) = sign_options.get(options::KEY_TYPE) {
            if key_type != KeyType::Pgp.to_string().as_str() {
                return Err(Error::InvalidArgumentError(
                    "checksum file only support pgp key type".to_string(),
                ));
            }
        }
        Ok(())
    }

    /* when assemble checksum signature when only create another .asc file separately */
    async fn assemble_data(
        &self,
        path: &PathBuf,
        data: Vec<Vec<u8>>,
        temp_dir: &PathBuf,
        _sign_options: &HashMap<String, String>,
    ) -> Result<(String, String)> {
        let temp_file = temp_dir.join(Uuid::new_v4().to_string());
        //convert bytes into string
        let result = String::from_utf8_lossy(&data[0]);
        fs::write(temp_file.clone(), result.as_bytes()).await?;
        Ok((
            temp_file.as_path().display().to_string(),
            format!("{}.{}", path.as_path().display(), FILE_EXTENSION),
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
        options.insert(options::DETACHED.to_string(), "false".to_string());
        let handler = CheckSumFileHandler::new();
        let result = handler.validate_options(&options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid argument: checksum file only support detached signature"
        );

        options.remove(options::DETACHED);
        let result = handler.validate_options(&options);
        assert!(result.is_ok());

        options.insert(options::DETACHED.to_string(), "true".to_string());
        options.insert(options::KEY_TYPE.to_string(), KeyType::Pgp.to_string());
        let result = handler.validate_options(&options);
        assert!(result.is_ok());

        options.insert(options::KEY_TYPE.to_string(), KeyType::X509EE.to_string());
        let result = handler.validate_options(&options);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "invalid argument: checksum file only support pgp key type"
        );
    }

    #[tokio::test]
    async fn test_assemble_data() {
        let handler = CheckSumFileHandler::new();
        let options = HashMap::new();
        let path = PathBuf::from("./test_data/test.txt");
        let data = vec![vec![1, 2, 3]];
        let temp_dir = env::temp_dir();
        let result = handler.assemble_data(&path, data, &temp_dir, &options).await;
        assert!(result.is_ok());
        let (temp_file, file_name) = result.expect("invoke assemble data should work");
        assert_eq!(temp_file.starts_with(temp_dir.to_str().unwrap()), true);
        assert_eq!(file_name, "./test_data/test.txt.asc");
    }
}
