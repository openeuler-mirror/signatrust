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

use super::dto::DataKeyDTO;
use crate::infra::database::pool::DbPool;
use crate::domain::datakey::entity::{DataKey, KeyState, KeyType, ParentKey, RevokedKey, Visibility, X509CRL, X509RevokeReason};
use crate::domain::datakey::repository::Repository;
use crate::util::error::{Result};
use async_trait::async_trait;
use chrono::Duration;
use chrono::Utc;
use sqlx::{MySql, Transaction};
use crate::infra::database::model::datakey::dto::X509CRLDTO;
use crate::infra::database::model::request_delete::dto::{PendingOperationDTO, RequestType, RevokedKeyDTO};
use crate::util::error;

const PUBLICKEY_PENDING_THRESHOLD: i32 = 3;
const PRIVATEKEY_PENDING_THRESHOLD: i32 = 1;

#[derive(Clone)]
pub struct DataKeyRepository {
    db_pool: DbPool,
}

impl DataKeyRepository {
    pub fn new(db_pool: DbPool) -> Self {
        Self {
            db_pool,
        }
    }

    async fn create_pending_operation(&self, pending_operation: PendingOperationDTO, tx: &mut Transaction<'_, MySql>) -> Result<()> {
        let _ : Option<PendingOperationDTO> = sqlx::query_as("INSERT IGNORE INTO pending_operation(user_id, key_id, user_email, create_at, request_type) VALUES (?, ?, ?, ?, ?)")
            .bind(pending_operation.user_id)
            .bind(pending_operation.key_id)
            .bind(pending_operation.user_email)
            .bind(pending_operation.create_at)
            .bind(pending_operation.request_type.to_string())
            .fetch_optional(tx)
            .await?;
        Ok(())
    }

    async fn delete_pending_operation(&self, user_id: i32, id: i32, request_type: RequestType, tx: &mut Transaction<'_, MySql>) -> Result<()> {
        let _ : Option<PendingOperationDTO> = sqlx::query_as("DELETE FROM pending_operation WHERE user_id = ? AND key_id = ? and request_type = ?")
            .bind(user_id)
            .bind(id)
            .bind(request_type.to_string())
            .fetch_optional(tx)
            .await?;
        Ok(())
    }

    async fn create_revoke_record(&self, key_id: i32, ca_id: i32, reason: X509RevokeReason, tx: &mut Transaction<'_, MySql>) -> Result<()> {
        let revoked = RevokedKeyDTO::new(key_id, ca_id, reason);
        let _ : Option<RevokedKeyDTO> = sqlx::query_as("INSERT IGNORE INTO x509_keys_revoked(ca_id, key_id, create_at, reason) VALUES (?, ?, ?, ?)")
            .bind(revoked.ca_id)
            .bind(revoked.key_id)
            .bind(revoked.create_at)
            .bind(revoked.reason)
            .fetch_optional(tx)
            .await?;
        Ok(())
    }

    async fn delete_revoke_record(&self, key_id: i32, ca_id: i32, tx: &mut Transaction<'_, MySql>) -> Result<()> {
        let _ : Option<RevokedKeyDTO> = sqlx::query_as("DELETE FROM x509_keys_revoked WHERE key_id = ? AND ca_id = ?")
            .bind(key_id)
            .bind(ca_id)
            .fetch_optional(tx)
            .await?;
        Ok(())
    }

    async fn _obtain_datakey_parent(&self, datakey: &mut DataKey) -> Result<()> {
        if let Some(parent) = datakey.parent_id {
            let result = self.get_by_id(parent).await;
            match result {
                Ok(parent) => {
                    datakey.parent_key = Some(ParentKey {
                        name: parent.name,
                        private_key: parent.private_key.clone(),
                        public_key: parent.public_key.clone(),
                        certificate: parent.certificate.clone(),
                        attributes: parent.attributes
                    })
                }
                _ => {
                    return Err(error::Error::DatabaseError("unable to find parent key".to_string()));
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Repository for DataKeyRepository {
    async fn create(&self, data_key: DataKey) -> Result<DataKey> {
        let dto = DataKeyDTO::try_from(data_key)?;
        let record : u64 = sqlx::query("INSERT INTO data_key(name, description, user, attributes, key_type, fingerprint, private_key, public_key, certificate, create_at, expire_at, key_state, visibility, parent_id, serial_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&dto.name)
            .bind(&dto.description)
            .bind(dto.user)
            .bind(dto.attributes)
            .bind(dto.key_type)
            .bind(dto.fingerprint)
            .bind(dto.private_key)
            .bind(dto.public_key)
            .bind(dto.certificate)
            .bind(dto.create_at)
            .bind(dto.expire_at)
            .bind(dto.key_state)
            .bind(dto.visibility)
            .bind(dto.parent_id)
            .bind(dto.serial_number)
            .execute(&self.db_pool)
            .await?.last_insert_id();
        let mut datakey = self.get_by_id(record as i32).await?;
        //fetch parent key if 'parent_id' exists.
        if let Err(err) = self._obtain_datakey_parent(&mut datakey).await {
            warn!("failed to create datakey {} {}", datakey.name, err);
            let _ = self.delete(record as i32).await;
            return Err(err);
        }

        Ok(datakey)
    }

    async fn delete(&self, id: i32) -> Result<()> {
        let _: Option<DataKeyDTO> = sqlx::query_as("DELETE FROM data_key WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(())
    }

    async fn get_all_keys(&self, key_type: Option<KeyType>, visibility: Visibility, user_id: i32) -> Result<Vec<DataKey>> {
        let dtos: Vec<DataKeyDTO> = match key_type {
            None => {
                if visibility == Visibility::Public {
                    sqlx::query_as(
                        "SELECT D.*, U.email AS user_email, GROUP_CONCAT(R.user_email) as request_delete_users, \
            GROUP_CONCAT(K.user_email) as request_revoke_users \
            FROM data_key D \
            INNER JOIN user U ON D.user = U.id \
            LEFT JOIN pending_operation R ON D.id = R.key_id and R.request_type = 'delete' \
            LEFT JOIN pending_operation K ON D.id = K.key_id and K.request_type = 'revoke' \
            WHERE D.key_state != ? AND D.visibility = ? \
            GROUP BY D.id")
                        .bind(KeyState::Deleted.to_string())
                        .bind(visibility.to_string())
                        .fetch_all(&self.db_pool)
                        .await?
                } else {
                    sqlx::query_as(
                        "SELECT D.*, U.email AS user_email, GROUP_CONCAT(R.user_email) as request_delete_users, \
            GROUP_CONCAT(K.user_email) as request_revoke_users \
            FROM data_key D \
            INNER JOIN user U ON D.user = U.id \
            LEFT JOIN pending_operation R ON D.id = R.key_id and R.request_type = 'delete' \
            LEFT JOIN pending_operation K ON D.id = K.key_id and K.request_type = 'revoke' \
            WHERE D.key_state != ? AND D.visibility = ? AND D.user = ? \
            GROUP BY D.id")
                        .bind(KeyState::Deleted.to_string())
                        .bind(visibility.to_string())
                        .bind(user_id)
                        .fetch_all(&self.db_pool)
                        .await?
                }
            }
            Some(key_t) => {
               if visibility == Visibility::Public {
                   sqlx::query_as(
                       "SELECT D.*, U.email AS user_email, GROUP_CONCAT(R.user_email) as request_delete_users, \
            GROUP_CONCAT(K.user_email) as request_revoke_users \
            FROM data_key D \
            INNER JOIN user U ON D.user = U.id \
            LEFT JOIN pending_operation R ON D.id = R.key_id and R.request_type = 'delete' \
            LEFT JOIN pending_operation K ON D.id = K.key_id and K.request_type = 'revoke' \
            WHERE D.key_state != ? AND \
            D.key_type = ? AND D.visibility = ? \
            GROUP BY D.id")
                       .bind(KeyState::Deleted.to_string())
                       .bind(key_t.to_string())
                       .bind(visibility.to_string())
                       .fetch_all(&self.db_pool)
                       .await?
               } else {
                   sqlx::query_as(
                       "SELECT D.*, U.email AS user_email, GROUP_CONCAT(R.user_email) as request_delete_users, \
            GROUP_CONCAT(K.user_email) as request_revoke_users \
            FROM data_key D \
            INNER JOIN user U ON D.user = U.id \
            LEFT JOIN pending_operation R ON D.id = R.key_id and R.request_type = 'delete' \
            LEFT JOIN pending_operation K ON D.id = K.key_id and K.request_type = 'revoke' \
            WHERE D.key_state != ? AND \
            D.key_type = ? AND D.visibility = ? AND D.user = ? \
            GROUP BY D.id")
                       .bind(KeyState::Deleted.to_string())
                       .bind(key_t.to_string())
                       .bind(visibility.to_string())
                       .bind(user_id)
                       .fetch_all(&self.db_pool)
                       .await?
               }
            }
        };
        let mut results = vec![];
        for dto in dtos.into_iter() {
            results.push(DataKey::try_from(dto)?);
        }
        Ok(results)
    }

    async fn get_keys_for_crl_update(&self, duration: Duration) -> Result<Vec<DataKey>> {
        let now = Utc::now();
        let dtos: Vec<DataKeyDTO> = sqlx::query_as(
            "SELECT D.id, D.name, D.description, D.user, D.attributes, D.key_type, D.fingerprint, D.private_key, D.public_key, D.certificate, D.create_at, D.expire_at, D.key_state, D.visibility, D.parent_id, D.serial_number, R.update_at AS x509_crl_update_at \
            FROM data_key D \
            LEFT JOIN x509_crl_content R ON D.id = R.ca_id \
            WHERE (D.key_type = ? OR D.key_type = ?) AND D.key_state != ?")
            .bind(KeyType::X509ICA.to_string())
            .bind(KeyType::X509CA.to_string())
            .bind(KeyState::Deleted.to_string())
            .fetch_all(&self.db_pool)
            .await?;
        let mut results = vec![];
        for dto in dtos.into_iter() {
            if dto.x509_crl_update_at.is_none() {
                results.push(DataKey::try_from(dto)?);
            } else {
                let update_at = dto.x509_crl_update_at.unwrap();
                if update_at + duration <= now {
                    results.push(DataKey::try_from(dto)?);
                }
            }
        }
        Ok(results)
    }

    async fn get_revoked_serial_number_by_parent_id(&self, id: i32) -> Result<Vec<RevokedKey>> {
        let dtos : Vec<RevokedKeyDTO> = sqlx::query_as(
            "SELECT R.*, D.serial_number \
             FROM x509_keys_revoked R \
             INNER JOIN data_key D ON R.key_id = D.id \
             WHERE R.ca_id = ? AND D.key_state = ?")
            .bind(id)
            .bind(KeyState::Revoked.to_string())
            .fetch_all(&self.db_pool)
            .await?;
        let mut results = vec![];
        for dto in dtos.into_iter() {
            results.push(RevokedKey::try_from(dto)?);
        }
        Ok(results)
    }

    async fn get_by_id(&self, id: i32) -> Result<DataKey> {
        let dto: DataKeyDTO = sqlx::query_as(
            "SELECT D.*, U.email AS user_email, GROUP_CONCAT(R.user_email) as request_delete_users, \
            GROUP_CONCAT(K.user_email) as request_revoke_users \
            FROM data_key D \
            INNER JOIN user U ON D.user = U.id \
            LEFT JOIN pending_operation R ON D.id = R.key_id and R.request_type = 'delete' \
            LEFT JOIN pending_operation K ON D.id = K.key_id and K.request_type = 'revoke' \
            WHERE D.id = ? AND D.key_state != ? \
            GROUP BY D.id")
            .bind(id)
            .bind(KeyState::Deleted.to_string())
            .fetch_one(&self.db_pool)
            .await?;
        Ok(DataKey::try_from(dto)?)
    }

    async fn get_by_parent_id(&self, parent_id: i32) -> Result<Vec<DataKey>> {
        let dtos: Vec<DataKeyDTO> = sqlx::query_as(
            "SELECT D.*, U.email AS user_email, GROUP_CONCAT(R.user_email) as request_delete_users, \
            GROUP_CONCAT(K.user_email) as request_revoke_users \
            FROM data_key D \
            INNER JOIN user U ON D.user = U.id \
            LEFT JOIN pending_operation R ON D.id = R.key_id and R.request_type = 'delete' \
            LEFT JOIN pending_operation K ON D.id = K.key_id and K.request_type = 'revoke' \
            WHERE D.parent_id = ? AND D.key_state != ? \
            GROUP BY D.id")
            .bind(parent_id)
            .bind(KeyState::Deleted.to_string())
            .fetch_all(&self.db_pool)
            .await?;
        let mut results = vec![];
        for dto in dtos.into_iter() {
            results.push(DataKey::try_from(dto)?);
        }
        Ok(results)
    }

    async fn get_by_name(&self, name: &str) -> Result<DataKey> {
        let dto: DataKeyDTO = sqlx::query_as(
            "SELECT D.*, U.email AS user_email, GROUP_CONCAT(R.user_email) as request_delete_users, \
            GROUP_CONCAT(K.user_email) as request_revoke_users \
            FROM data_key D \
            INNER JOIN user U ON D.user = U.id \
            LEFT JOIN pending_operation R ON D.id = R.key_id and R.request_type = 'delete' \
            LEFT JOIN pending_operation K ON D.id = K.key_id and K.request_type = 'revoke' \
            WHERE D.name = ? AND D.key_state != ? \
            GROUP BY D.id")
            .bind(name)
            .bind(KeyState::Deleted.to_string())
            .fetch_one(&self.db_pool)
            .await?;
        Ok(DataKey::try_from(dto)?)
    }

    async fn update_state(&self, id: i32, state: KeyState) -> Result<()> {
        //Note: if the key in deleted status, it cannot be updated to other states
        let _: Option<DataKeyDTO>  = sqlx::query_as("UPDATE data_key SET key_state = ? WHERE id = ? AND key_state != ?")
            .bind(state.to_string())
            .bind(id)
            .bind(KeyState::Deleted.to_string())
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(())
    }

    async fn update_key_data(&self, data_key: DataKey) -> Result<()> {
        //Note: if the key in deleted status, it cannot be updated to other states
        let dto = DataKeyDTO::try_from(data_key)?;
        let _: Option<DataKeyDTO>  = sqlx::query_as("UPDATE data_key SET serial_number = ?, fingerprint = ?, private_key = ?, public_key = ?, certificate = ? WHERE id = ? AND key_state != ?")
            .bind(dto.serial_number)
            .bind(dto.fingerprint)
            .bind(dto.private_key)
            .bind(dto.public_key)
            .bind(dto.certificate)
            .bind(dto.id)
            .bind(KeyState::Deleted.to_string())
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(())
    }

    async fn get_enabled_key_by_type_and_name(&self, key_type: String, name: String) -> Result<DataKey> {
        let dto: DataKeyDTO = sqlx::query_as(
            "SELECT D.*, U.email AS user_email, GROUP_CONCAT(R.user_email) as request_delete_users, \
            GROUP_CONCAT(K.user_email) as request_revoke_users \
            FROM data_key D \
            INNER JOIN user U ON D.user = U.id \
            LEFT JOIN pending_operation R ON D.id = R.key_id and R.request_type = 'delete' \
            LEFT JOIN pending_operation K ON D.id = K.key_id and K.request_type = 'revoke' \
            WHERE D.name = ? AND D.key_type = ? AND D.key_state = ? \
            GROUP BY D.id")
            .bind(name)
            .bind(key_type)
            .bind(KeyState::Enabled.to_string())
            .fetch_one(&self.db_pool)
            .await?;
        let mut datakey = DataKey::try_from(dto)?;
        self._obtain_datakey_parent(&mut datakey).await?;
        return Ok(datakey)
    }

    async fn request_delete_key(&self, user_id: i32, user_email: String, id: i32, public_key: bool) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        let threshold = if public_key { PUBLICKEY_PENDING_THRESHOLD } else { PRIVATEKEY_PENDING_THRESHOLD };
        //1. update key state to pending delete if needed.
        let _: Option<DataKeyDTO> = sqlx::query_as(
            "UPDATE data_key SET key_state = ? \
            WHERE id = ?")
            .bind(KeyState::PendingDelete.to_string())
            .bind(id)
            .fetch_optional(&mut tx)
            .await?;
        //2. add request delete record
        let pending_delete = PendingOperationDTO::new_for_delete(id, user_id, user_email);
        self.create_pending_operation(pending_delete, &mut tx).await?;
        //3. delete datakey if pending delete count >= threshold
        let _: Option<DataKeyDTO> = sqlx::query_as(
            "UPDATE data_key SET key_state = ? \
            WHERE id = ? AND ( \
            SELECT COUNT(*) FROM pending_operation WHERE key_id = ?) >= ?")
            .bind(KeyState::Deleted.to_string())
            .bind(id)
            .bind(id)
            .bind(threshold)
            .fetch_optional(&mut tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn request_revoke_key(&self, user_id: i32, user_email: String, id: i32, parent_id: i32, reason: X509RevokeReason, public_key: bool) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        let threshold = if public_key { PUBLICKEY_PENDING_THRESHOLD } else { PRIVATEKEY_PENDING_THRESHOLD };
        //1. update key state to pending delete if needed.
        let _: Option<DataKeyDTO> = sqlx::query_as(
            "UPDATE data_key SET key_state = ? \
            WHERE id = ?")
            .bind(KeyState::PendingRevoke.to_string())
            .bind(id)
            .fetch_optional(&mut tx)
            .await?;
        //2. add request revoke pending record
        let pending_revoke = PendingOperationDTO::new_for_revoke(id, user_id, user_email);
        self.create_pending_operation(pending_revoke, &mut tx).await?;
        //3. add revoked record
        self.create_revoke_record(id, parent_id, reason, &mut tx).await?;
        //4. mark datakey revoked if pending revoke count >= threshold
        let _: Option<DataKeyDTO> = sqlx::query_as(
            "UPDATE data_key SET key_state = ? \
            WHERE id = ? AND ( \
            SELECT COUNT(*) FROM pending_operation WHERE key_id = ?) >= ?")
            .bind(KeyState::Revoked.to_string())
            .bind(id)
            .bind(id)
            .bind(threshold)
            .fetch_optional(&mut tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn cancel_delete_key(&self, user_id: i32, id: i32) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        //1. delete pending delete record
        self.delete_pending_operation(user_id, id, RequestType::Delete, &mut tx).await?;
        //2. update status if there is not any pending delete record.
        let _: Option<DataKeyDTO> = sqlx::query_as(
            "UPDATE data_key SET key_state = ? \
            WHERE id = ? AND ( \
            SELECT COUNT(*) FROM pending_operation WHERE key_id = ?) = ?")
            .bind(KeyState::Disabled.to_string())
            .bind(id)
            .bind(id)
            .bind(0)
            .fetch_optional(&mut tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn cancel_revoke_key(&self, user_id: i32, id: i32, parent_id: i32) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        //1. delete pending delete record
        self.delete_pending_operation(user_id, id, RequestType::Revoke, &mut tx).await?;
        //2. delete revoked record
        self.delete_revoke_record(id, parent_id, &mut tx).await?;
        //3. update status if there is not any pending delete record.
        let _: Option<DataKeyDTO> = sqlx::query_as(
            "UPDATE data_key SET key_state = ? \
            WHERE id = ? AND ( \
            SELECT COUNT(*) FROM pending_operation WHERE key_id = ?) = ?")
            .bind(KeyState::Disabled.to_string())
            .bind(id)
            .bind(id)
            .bind(0)
            .fetch_optional(&mut tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn get_x509_crl_by_ca_id(&self, id: i32) -> Result<X509CRL> {
        let dto: X509CRLDTO = sqlx::query_as(
            "SELECT * from x509_crl_content WHERE ca_id = ?")
            .bind(id)
            .fetch_one(&self.db_pool)
            .await?;
        Ok( X509CRL::try_from(dto)?)
    }

    async fn upsert_x509_crl(&self, crl: X509CRL) -> Result<()> {
        let dto = X509CRLDTO::try_from(crl)?;
        match self.get_x509_crl_by_ca_id(dto.ca_id).await {
            Ok(_) => {
                sqlx::query(
                    "UPDATE x509_crl_content SET data = ?, create_at = ?, update_at = ? WHERE ca_id = ?")
                    .bind(dto.data)
                    .bind(dto.create_at)
                    .bind(dto.update_at)
                    .bind(dto.ca_id)
                    .execute(&self.db_pool)
                    .await?;
            }
            Err(_) => {
                sqlx::query(
                    "INSERT INTO x509_crl_content(ca_id, data, create_at, update_at) VALUES (?, ?, ?, ?)")
                    .bind(dto.ca_id)
                    .bind(dto.data)
                    .bind(dto.create_at)
                    .bind(dto.update_at)
                    .execute(&self.db_pool)
                    .await?;
            }
        }
        Ok(())
    }
}
