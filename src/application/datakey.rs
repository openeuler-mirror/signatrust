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
use crate::util::error::{Error, Result};
use async_trait::async_trait;
use crate::domain::datakey::entity::{DataKey, KeyState, Visibility};
use tokio::time::{Duration, self};

use crate::util::signer_container::DataKeyContainer;
use std::collections::HashMap;
use std::sync::{Arc};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use crate::presentation::handler::control::model::user::dto::UserIdentity;

#[async_trait]
pub trait KeyService: Send + Sync{
    async fn create(&self, data: &mut DataKey) -> Result<DataKey>;
    async fn import(&self, data: &mut DataKey) -> Result<DataKey>;
    async fn key_name_exists(&self, name: &String) -> Result<bool>;
    async fn get_by_visibility(&self, user: Option<UserIdentity>,  visibility: Visibility) -> Result<Vec<DataKey>>;
    async fn get_all(&self) -> Result<Vec<DataKey>>;
    async fn get_one(&self, user: Option<UserIdentity>, id: i32) -> Result<DataKey>;
    async fn request_delete(&self, user: UserIdentity, id: i32) -> Result<()>;
    async fn cancel_delete(&self, user: UserIdentity, id: i32) -> Result<()>;
    async fn export_one(&self, user: Option<UserIdentity>, id: i32) -> Result<DataKey>;
    async fn enable(&self, user: Option<UserIdentity>, id: i32) -> Result<()>;
    async fn disable(&self, user: Option<UserIdentity>, id: i32) -> Result<()>;
    async fn sign(&self, key_type: String, key_name: String, options: &HashMap<String, String>, data: Vec<u8>) ->Result<Vec<u8>>;

    //method below used for maintenance
    fn start_cache_cleanup_loop(&self, cancel_token: CancellationToken) -> Result<()>;
    fn start_key_rotate_loop(&self, cancel_token: CancellationToken) -> Result<()>;
}



pub struct DBKeyService<R, S>
where
    R: DatakeyRepository + Clone + 'static,
    S: SignBackend + ?Sized + 'static
{
    repository: R,
    sign_service: Arc<RwLock<Box<S>>>,
    container: DataKeyContainer<R>
}

impl<R, S> DBKeyService<R, S>
    where
        R: DatakeyRepository + Clone + 'static,
        S: SignBackend + ?Sized + 'static
{
    pub fn new(repository: R, sign_service: Box<S>) -> Self {
        Self {
            repository: repository.clone(),
            sign_service: Arc::new(RwLock::new(sign_service)),
            container: DataKeyContainer::new(repository)
        }
    }

    async fn get_and_check_permission(&self, user: Option<UserIdentity>, id: i32) -> Result<DataKey> {
        let key = self.repository.get_by_id(id).await?;
        if key.visibility == Visibility::Public {
            return Ok(key);
        }
        if user.is_none() || key.user != user.unwrap().id {
            return Err(Error::UnprivilegedError);
        }
        Ok(key)
    }
}

#[async_trait]
impl<R, S> KeyService for DBKeyService<R, S>
where
    R: DatakeyRepository + Clone + 'static,
    S: SignBackend + ?Sized + 'static
{
    async fn create(&self, data: &mut DataKey) -> Result<DataKey> {
        self.sign_service.read().await.generate_keys(data).await?;
        self.repository.create(data.clone()).await
    }

    async fn import(&self, data: &mut DataKey) -> Result<DataKey> {
        self.sign_service.read().await.validate_and_update(data).await?;
        self.repository.create(data.clone()).await
    }

    async fn key_name_exists(&self, name: &String) -> Result<bool> {
        if self.repository.get_by_name(name).await.is_ok() {
            return Ok(true);
        }
        Ok(false)
    }

    async fn get_by_visibility(&self, user: Option<UserIdentity>, visibility: Visibility) -> Result<Vec<DataKey>> {
        if visibility == Visibility::Private {
            if user.is_none() {
                return Err(Error::UnprivilegedError);
            }
            return self.repository.get_private_keys(user.unwrap().id).await;
        }
        self.repository.get_public_keys().await
    }

    async fn get_all(&self) -> Result<Vec<DataKey>> {
        self.repository.get_all_keys().await
    }

    async fn get_one(&self, user: Option<UserIdentity>,  id: i32) -> Result<DataKey> {
        self.get_and_check_permission(user, id).await
    }

    async fn request_delete(&self, user: UserIdentity, id: i32) -> Result<()> {
        let user_id = user.id;
        let user_email = user.email.clone();
        let key = self.get_and_check_permission(Some(user), id).await?;
        if key.key_state == KeyState::Enabled {
            return Err(Error::ParameterError("enabled key does not support delete".to_string()));
        }
        match key.visibility {
            Visibility::Public => {
                self.repository.request_delete_public_key(user_id, user_email, key.id).await
            }
            Visibility::Private => {
                self.repository.delete_private_key(key.id, user_id).await
            }
        }
    }

    async fn cancel_delete(&self, user: UserIdentity, id: i32) -> Result<()> {
        let user_id = user.id;
        let key = self.get_and_check_permission(Some(user), id).await?;
        if key.visibility == Visibility::Private {
            return Err(Error::ParameterError("private key does not support cancel delete".to_string()));
        }
        self.repository.cancel_delete_public_key(user_id, key.id).await
    }

    async fn export_one(&self, user: Option<UserIdentity>, id: i32) -> Result<DataKey> {
        let mut key = self.get_and_check_permission(user, id).await?;
        self.sign_service.read().await.decode_public_keys(&mut key).await?;
        Ok(key)
    }

    async fn enable(&self, user: Option<UserIdentity>, id: i32) -> Result<()> {
        let key = self.get_and_check_permission(user, id).await?;
        self.repository.update_state(key.id, KeyState::Enabled).await
    }

    async fn disable(&self, user: Option<UserIdentity>, id: i32) -> Result<()> {
        let key = self.get_and_check_permission(user, id).await?;
        self.repository.update_state(key.id, KeyState::Disabled).await
    }

    async fn sign(&self, key_type: String, key_name: String, options: &HashMap<String, String>, data: Vec<u8>) -> Result<Vec<u8>> {
        self.sign_service.read().await.sign(
            &self.container.get_data_key(key_type, key_name).await?, data, options.clone()).await
    }

    fn start_cache_cleanup_loop(&self, cancel_token: CancellationToken) -> Result<()> {
        let container = self.container.clone();
        let mut interval = time::interval(Duration::from_secs(120));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        info!("start to clear the container keys");
                        container.clear_keys().await;
                    }
                    _ = cancel_token.cancelled() => {
                        info!("cancel token received, will quit datakey clean loop");
                        break;
                    }
                }
            }

        });
        Ok(())
    }

    fn start_key_rotate_loop(&self, cancel_token: CancellationToken) -> Result<()> {
        let sign_service = self.sign_service.clone();
        let mut interval = time::interval(Duration::from_secs(60 * 60 * 2));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        info!("start to rotate the keys");
                        match sign_service.write().await.rotate_key().await {
                            Ok(changed) => {
                                if changed {
                                    info!("keys has been successfully rotated");
                                }
                            }
                            Err(e) => {
                                error!("failed to rotate key: {}", e);
                            }
                        }
                    }
                    _ = cancel_token.cancelled() => {
                        info!("cancel token received, will quit key rotate loop");
                        break;
                    }
                }
            }

        });
        Ok(())
    }
}
