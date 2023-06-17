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
use crate::domain::datakey::entity::{DataKey, KeyAction, KeyState, X509CRL, X509RevokeReason};
use tokio::time::{Duration, self};

use crate::util::signer_container::DataKeyContainer;
use std::collections::HashMap;
use std::sync::{Arc};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use crate::domain::datakey::entity::KeyType::{OpenPGP, X509CA, X509EE, X509ICA};
use crate::presentation::handler::control::model::user::dto::UserIdentity;

#[async_trait]
pub trait KeyService: Send + Sync{
    async fn create(&self, data: &mut DataKey) -> Result<DataKey>;
    async fn import(&self, data: &mut DataKey) -> Result<DataKey>;
    async fn get_by_name(&self, name: &str) -> Result<DataKey>;
    async fn get_all(&self) -> Result<Vec<DataKey>>;
    async fn get_one(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<DataKey>;
    //get keys content
    async fn export_one(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<DataKey>;
    async fn export_cert_crl(&self, user: Option<UserIdentity>,id_or_name: String) -> Result<X509CRL>;
    //keys related operation
    async fn request_delete(&self, user: UserIdentity, id_or_name: String) -> Result<()>;
    async fn cancel_delete(&self, user: UserIdentity, id_or_name: String) -> Result<()>;
    async fn request_revoke(&self, user: UserIdentity, id_or_name: String, reason: X509RevokeReason) -> Result<()>;
    async fn cancel_revoke(&self, user: UserIdentity, id_or_name: String) -> Result<()>;
    async fn enable(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<()>;
    async fn disable(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<()>;
    //used for data server
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

    async fn get_and_check_permission(&self, _user: Option<UserIdentity>, id_or_name: String, action: KeyAction) -> Result<DataKey> {
        let id = id_or_name.parse::<i32>();
        let data_key: DataKey = match id {
            Ok(id) => {
                self.repository.get_by_id(id).await?
            }
            Err(_) => {
                self.repository.get_by_name(&id_or_name).await?
            }
        };
        self.validate_type_and_state(&data_key, action)?;
        Ok(data_key)
    }

    fn validate_type_and_state(&self, key: &DataKey, key_action: KeyAction) -> Result<()> {
        let valid_action_by_key_type = HashMap::from([
            (OpenPGP, vec![KeyAction::Delete, KeyAction::CancelDelete, KeyAction::Disable, KeyAction::Enable, KeyAction::Sign, KeyAction::Read]),
            (X509CA, vec![KeyAction::Delete, KeyAction::CancelDelete, KeyAction::Disable, KeyAction::Enable, KeyAction::IssueCert, KeyAction::Read]),
            (X509ICA, vec![KeyAction::Delete, KeyAction::CancelDelete, KeyAction::Revoke, KeyAction::CancelRevoke, KeyAction::Disable, KeyAction::Enable, KeyAction::Read, KeyAction::IssueCert]),
            (X509EE, vec![KeyAction::Delete, KeyAction::CancelDelete, KeyAction::Revoke, KeyAction::CancelRevoke, KeyAction::Disable, KeyAction::Enable, KeyAction::Read, KeyAction::Sign]),
        ]);

        let valid_state_by_key_action = HashMap::from([
            (KeyAction::Delete, vec![KeyState::Disabled, KeyState::Revoked, KeyState::PendingDelete]),
            (KeyAction::CancelDelete, vec![KeyState::PendingDelete]),
            (KeyAction::Revoke, vec![KeyState::Disabled, KeyState::PendingRevoke]),
            (KeyAction::CancelRevoke, vec![KeyState::PendingRevoke]),
            (KeyAction::Enable, vec![KeyState::Disabled]),
            (KeyAction::Disable, vec![KeyState::Enabled]),
            (KeyAction::Sign, vec![KeyState::Enabled, KeyState::PendingDelete, KeyState::PendingRevoke]),
            (KeyAction::IssueCert, vec![KeyState::Enabled, KeyState::PendingDelete, KeyState::PendingRevoke]),
            (KeyAction::Read, vec![KeyState::Enabled, KeyState::PendingDelete, KeyState::PendingRevoke]),
        ]);
        match valid_action_by_key_type.get(&key.key_type) {
            None => {
                return Err(Error::ConfigError("key type is missing, please check the key type".to_string()));
            }
            Some(actions) => {
                if !actions.contains(&key_action) {
                    return Err(Error::ActionsNotAllowedError(format!("action '{}' is not permitted for key type '{}'", key_action, key.key_type)));
                }
            }
        }
        return match valid_state_by_key_action.get(&key_action) {
            None => {
                Err(Error::ConfigError("key action is missing, please check the key action".to_string()))
            }
            Some(states) => {
                if states.contains(&key.key_state) {
                    Ok(())
                } else {
                    Err(Error::ActionsNotAllowedError(format!("action '{}' is not permitted for state '{}'", key_action, key.key_state)))
                }
            }
        }
    }
}

#[async_trait]
impl<R, S> KeyService for DBKeyService<R, S>
where
    R: DatakeyRepository + Clone + 'static,
    S: SignBackend + ?Sized + 'static
{
    async fn create(&self, data: &mut DataKey) -> Result<DataKey> {
        //we need to create a key in database first, then generate sensitive data
        let mut key = self.repository.create(data.clone()).await?;
        match self.sign_service.read().await.generate_keys(&mut key).await {
            Ok(_) => {
                self.repository.update_key_data(key.clone()).await?;
                Ok(key)
            }
            Err(e) => {
                self.repository.delete(key.id).await?;
                Err(e)
            }
        }
    }

    async fn import(&self, data: &mut DataKey) -> Result<DataKey> {
        self.sign_service.read().await.validate_and_update(data).await?;
        self.repository.create(data.clone()).await
    }

    async fn get_by_name(&self, name: &str) -> Result<DataKey> {
        self.repository.get_by_name(name).await
    }

    async fn get_all(&self) -> Result<Vec<DataKey>> {
        self.repository.get_all_keys().await
    }

    async fn get_one(&self, user: Option<UserIdentity>,  id_or_name: String) -> Result<DataKey> {
        let datakey = self.get_and_check_permission(user, id_or_name, KeyAction::Read).await?;
        Ok(datakey)

    }

    async fn export_one(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<DataKey> {
        let mut key = self.get_and_check_permission(user, id_or_name, KeyAction::Read).await?;
        self.sign_service.read().await.decode_public_keys(&mut key).await?;
        Ok(key)
    }

    async fn export_cert_crl(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<X509CRL> {
        let key = self.get_and_check_permission(user, id_or_name, KeyAction::Read).await?;
        let crl = self.repository.get_x509_crl_by_ca_id(key.id).await?;
        Ok(crl)
    }

    async fn request_delete(&self, user: UserIdentity, id_or_name: String) -> Result<()> {
        let user_id = user.id;
        let user_email = user.email.clone();
        let key = self.get_and_check_permission(Some(user), id_or_name, KeyAction::Delete).await?;
        self.repository.request_delete_key(user_id, user_email, key.id).await
    }

    async fn cancel_delete(&self, user: UserIdentity, id_or_name: String) -> Result<()> {
        let user_id = user.id;
        let key = self.get_and_check_permission(Some(user), id_or_name, KeyAction::CancelDelete).await?;
        self.repository.cancel_delete_key(user_id, key.id).await
    }

    async fn request_revoke(&self, user: UserIdentity, id_or_name: String,  reason: X509RevokeReason) -> Result<()> {
        let user_id = user.id;
        let user_email = user.email.clone();
        let key = self.get_and_check_permission(Some(user), id_or_name, KeyAction::Revoke).await?;
        self.repository.request_revoke_key(user_id, user_email, key.id, reason).await?;
        Ok(())
    }

    async fn cancel_revoke(&self, user: UserIdentity, id_or_name: String) -> Result<()> {
        let user_id = user.id;
        let key = self.get_and_check_permission(Some(user), id_or_name, KeyAction::CancelRevoke).await?;
        self.repository.cancel_revoke_key(user_id, key.id).await?;
        Ok(())
    }

    async fn enable(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<()> {
        let key = self.get_and_check_permission(user, id_or_name, KeyAction::Enable).await?;
        self.repository.update_state(key.id, KeyState::Enabled).await
    }

    async fn disable(&self, user: Option<UserIdentity>, id_or_name: String) -> Result<()> {
        let key = self.get_and_check_permission(user, id_or_name, KeyAction::Disable).await?;
        self.repository.update_state(key.id, KeyState::Disabled).await
    }

    async fn sign(&self, key_type: String, key_name: String, options: &HashMap<String, String>, data: Vec<u8>) -> Result<Vec<u8>> {
        let key = self.container.get_data_key(key_type, key_name).await?;
        self.sign_service.read().await.sign(&key, data, options.clone()).await
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
