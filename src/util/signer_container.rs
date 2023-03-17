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
use crate::infra::sign::traits::SignPlugins;
use std::sync::{Arc};
use tokio::sync::RwLock;
use crate::util::error::Result;
use crate::infra::database::model::datakey::repository::EncryptedDataKeyRepository;
use crate::model::datakey::repository::Repository;
use crate::infra::sign::signers::Signers;

pub struct DataKeyContainer {
    repository: Arc<EncryptedDataKeyRepository>,
    containers: Arc<RwLock<HashMap<String, Arc<Box<dyn SignPlugins>>>>>,
}

impl DataKeyContainer {
    pub fn new(repository: Arc<EncryptedDataKeyRepository>) -> DataKeyContainer {
        Self {
            repository,
            containers: Arc::new(RwLock::new(HashMap::new()))
        }
    }

    pub async fn get_signer(&self, key_type: String, key_name: String) -> Result<Arc<Box<dyn SignPlugins>>> {
        let identity = self.get_identity(&key_type, &key_name);
        if let Some(signer) = self.containers.read().await.get(&identity) {
            return Ok(signer.clone())
        }
        let datakey = self.repository.get_enabled_key_by_type_and_name(key_type, key_name).await?;
        let new = Signers::load_from_data_key(&datakey)?;
        self.containers.write().await.insert(identity, new.clone());
        Ok(new)
    }

    fn get_identity(&self, key_type: &str, key_name: &str) -> String {
        format!("{}-{}",key_type, key_name)
    }
}