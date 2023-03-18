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

use crate::domain::datakey::repository::Repository as DatakeyRepository;
use crate::domain::sign_service::SignBackend;
use crate::util::error::{Result};
use async_trait::async_trait;
use crate::domain::datakey::entity::{DataKey, KeyState};
use crate::presentation::handler::control::model::datakey::dto::DataKeyDTO;

use crate::util::signer_container::DataKeyContainer;
use std::collections::HashMap;

#[async_trait]
pub trait KeyService: Send + Sync{
    async fn create(&self, data: DataKeyDTO) -> Result<DataKey>;
    async fn get_all(&self) -> Result<Vec<DataKey>>;
    async fn get_one(&self, id: i32) -> Result<DataKey>;
    async fn delete_one(&self, id: i32) -> Result<()>;
    async fn export_one(&self, id: i32) -> Result<DataKey>;
    async fn enable(&self, id: i32) -> Result<()>;
    async fn disable(&self, id: i32) -> Result<()>;
    async fn sign(&self, key_type: String, key_name: String, options: &HashMap<String, String>, data: Vec<u8>) ->Result<Vec<u8>>;
}



pub struct DBKeyService<R, S>
where
    R: DatakeyRepository + Clone,
    S: SignBackend + ?Sized
{
    repository: R,
    sign_service: Box<S>,
    container: DataKeyContainer<R>
}

impl<R, S> DBKeyService<R, S>
    where
        R: DatakeyRepository + Clone,
        S: SignBackend + ?Sized
{
    pub fn new(repository: R, sign_service: Box<S>) -> Self {
        Self {
            repository: repository.clone(),
            sign_service,
            container: DataKeyContainer::new(repository)
        }
    }
}

#[async_trait]
impl<R, S> KeyService for DBKeyService<R, S>
where
    R: DatakeyRepository + Clone,
    S: SignBackend + ?Sized
{
    async fn create(&self, data: DataKeyDTO) -> Result<DataKey> {
        let mut key = DataKey::try_from(data)?;
        self.sign_service.generate_keys(&mut key).await?;
        self.repository.create(key).await
    }

    async fn get_all(&self) -> Result<Vec<DataKey>> {
        self.repository.get_all().await
    }

    async fn get_one(&self, id: i32) -> Result<DataKey> {
        self.repository.get_by_id(id).await
    }

    async fn delete_one(&self, id: i32) -> Result<()> {
        let key = self.repository.get_by_id(id).await?;
        self.repository.delete_by_id(key.id).await
    }

    async fn export_one(&self, id: i32) -> Result<DataKey> {
        let mut key = self.repository.get_by_id(id).await?;
        self.sign_service.decode_public_keys(&mut key).await?;
        Ok(key)
    }

    async fn enable(&self, id: i32) -> Result<()> {
        let key = self.repository.get_by_id(id).await?;
        self.repository.update_state(key.id, KeyState::Enabled).await
    }

    async fn disable(&self, id: i32) -> Result<()> {
        let key = self.repository.get_by_id(id).await?;
        self.repository.update_state(key.id, KeyState::Disabled).await
    }

    async fn sign(&self, key_type: String, key_name: String, options: &HashMap<String, String>, data: Vec<u8>) -> Result<Vec<u8>> {
        self.sign_service.sign(
            &self.container.get_data_key(key_type, key_name).await?, data, options.clone()).await
    }
}
