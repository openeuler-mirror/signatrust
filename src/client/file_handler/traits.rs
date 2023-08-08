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

use crate::util::error::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;

#[async_trait]
pub trait FileHandler: Send + Sync {
    fn validate_options(&self, _sign_options: &HashMap<String, String>) -> Result<()>;
    async fn split_data(
        &self,
        path: &PathBuf,
        _sign_options: &mut HashMap<String, String>,
        _key_attributes: &HashMap<String, String>
    ) -> Result<Vec<Vec<u8>>> {
        let content = fs::read(path).await?;
        Ok(vec![content])
    }
    //return the temporary file path and signature file name
    async fn assemble_data(
        &self,
        path: &PathBuf,
        data: Vec<Vec<u8>>,
        temp_dir: &PathBuf,
        sign_options: &HashMap<String, String>,
        key_attributes: &HashMap<String, String>
    ) -> Result<(String, String)>;
}
