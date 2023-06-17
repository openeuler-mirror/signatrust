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
use crate::domain::datakey::entity::{DataKey, KeyState, ParentKey, X509CRL, X509RevokeReason};
use crate::domain::datakey::repository::Repository;
use crate::util::error::{Result};
use async_trait::async_trait;
use std::boxed::Box;
use chrono::{Utc};
use sqlx::{MySql, Transaction};
use crate::infra::database::model::datakey::dto::X509CRLDTO;
use crate::infra::database::model::request_delete::dto::{PendingOperationDTO, RequestType};
use crate::util::error;

const PENDING_THRESHOLD: i32 = 3;

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

    async fn create_request_delete(&self, user_id: i32, user_email: String, id: i32, tx: &mut Transaction<'_, MySql>) -> Result<()> {
        let pending_operation = PendingOperationDTO::new_for_delete(id, user_id, user_email, None);
        let _ : Option<PendingOperationDTO> = sqlx::query_as("INSERT IGNORE INTO pending_operation(user_id, key_id, user_email, create_at, request_type, reason) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(user_id)
            .bind(id)
            .bind(pending_operation.user_email)
            .bind(Utc::now())
            .bind(pending_operation.request_type.to_string())
            .bind(pending_operation.reason)
            .fetch_optional(tx)
            .await?;
        Ok(())
    }

    async fn create_request_revoke(&self, user_id: i32, user_email: String, id: i32, reason: String, tx: &mut Transaction<'_, MySql>) -> Result<()> {
        let pending_operation = PendingOperationDTO::new_for_revoke(id, user_id, user_email, reason);
        let _ : Option<PendingOperationDTO> = sqlx::query_as("INSERT IGNORE INTO pending_operation(user_id, key_id, user_email, create_at, request_type, reason) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(user_id)
            .bind(id)
            .bind(pending_operation.user_email)
            .bind(Utc::now())
            .bind(pending_operation.request_type.to_string())
            .bind(pending_operation.reason)
            .fetch_optional(tx)
            .await?;
        Ok(())
    }

    async fn delete_request_delete(&self, user_id: i32, id: i32,  tx: &mut Transaction<'_, MySql>) -> Result<()> {
        let _ : Option<PendingOperationDTO> = sqlx::query_as("DELETE FROM pending_operation WHERE user_id = ? AND key_id = ? and request_type = ?")
            .bind(user_id)
            .bind(id)
            .bind(RequestType::Delete.to_string())
            .fetch_optional(tx)
            .await?;
        Ok(())
    }

    async fn delete_request_revoke(&self, user_id: i32, id: i32,  tx: &mut Transaction<'_, MySql>) -> Result<()> {
        let _ : Option<PendingOperationDTO> = sqlx::query_as("DELETE FROM pending_operation WHERE user_id = ? AND key_id = ? and request_type = ?")
            .bind(user_id)
            .bind(id)
            .bind(RequestType::Revoke.to_string())
            .fetch_optional(tx)
            .await?;
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
                Err(error::Error::NotFoundError) => {
                    let _ = self.delete(record as i32).await;
                    return Err(error::Error::InvalidArgumentError("parent key does not exist".to_string()));
                }
                _ => {
                    let _ = self.delete(record as i32).await;
                    return Err(error::Error::DatabaseError("unable to find parent key".to_string()));
                }
            }
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

    async fn get_all_keys(&self) -> Result<Vec<DataKey>> {
        let dtos: Vec<DataKeyDTO> = sqlx::query_as(
            "SELECT D.*, U.email AS user_email, GROUP_CONCAT(R.user_email) as request_delete_users, \
            GROUP_CONCAT(K.user_email) as request_revoke_users \
            FROM data_key D \
            INNER JOIN user U ON D.user = U.id \
            LEFT JOIN pending_operation R ON D.id = R.key_id and R.request_type = 'delete' \
            LEFT JOIN pending_operation K ON D.id = K.key_id and K.request_type = 'revoke' \
            WHERE D.key_state != ? \
            GROUP BY D.id")
            .bind(KeyState::Deleted.to_string())
            .fetch_all(&self.db_pool)
            .await?;
        let mut results = vec![];
        for dto in dtos.into_iter() {
            results.push(DataKey::try_from(dto)?);
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
        Ok(DataKey::try_from(dto)?)
    }

    async fn request_delete_key(&self, user_id: i32, user_email: String, id: i32) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        //1. update key state to pending delete if needed.
        let _: Option<DataKeyDTO> = sqlx::query_as(
            "UPDATE data_key SET key_state = ? \
            WHERE id = ?")
            .bind(KeyState::PendingDelete.to_string())
            .bind(id)
            .fetch_optional(&mut tx)
            .await?;
        //2. add request delete record
        self.create_request_delete(user_id, user_email, id, &mut tx).await?;
        //3. delete datakey if pending delete count >= threshold
        let _: Option<DataKeyDTO> = sqlx::query_as(
            "UPDATE data_key SET key_state = ? \
            WHERE id = ? AND ( \
            SELECT COUNT(*) FROM pending_operation WHERE key_id = ?) >= ?")
            .bind(KeyState::Deleted.to_string())
            .bind(id)
            .bind(id)
            .bind(PENDING_THRESHOLD)
            .fetch_optional(&mut tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn request_revoke_key(&self, user_id: i32, user_email: String, id: i32, reason: X509RevokeReason) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        //1. update key state to pending delete if needed.
        let _: Option<DataKeyDTO> = sqlx::query_as(
            "UPDATE data_key SET key_state = ? \
            WHERE id = ?")
            .bind(KeyState::PendingRevoke.to_string())
            .bind(id)
            .fetch_optional(&mut tx)
            .await?;
        //2. add request revoke record
        self.create_request_revoke(user_id, user_email, id,  reason.to_string(), &mut tx).await?;
        //3. delete datakey if pending delete count >= threshold
        let _: Option<DataKeyDTO> = sqlx::query_as(
            "UPDATE data_key SET key_state = ? \
            WHERE id = ? AND ( \
            SELECT COUNT(*) FROM pending_operation WHERE key_id = ?) >= ?")
            .bind(KeyState::Revoked.to_string())
            .bind(id)
            .bind(id)
            .bind(PENDING_THRESHOLD)
            .fetch_optional(&mut tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn cancel_delete_key(&self, user_id: i32, id: i32) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        //1. delete pending delete record
        self.delete_request_delete(user_id, id, &mut tx).await?;
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

    async fn cancel_revoke_key(&self, user_id: i32, id: i32) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        //1. delete pending delete record
        self.delete_request_revoke(user_id, id, &mut tx).await?;
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

    async fn get_x509_crl_by_ca_id(&self, id: i32) -> Result<X509CRL> {
        let dto: X509CRLDTO = sqlx::query_as(
            "SELECT * from x509_crl_content WHERE ca_id = ?")
            .bind(id)
            .fetch_one(&self.db_pool)
            .await?;
        Ok( X509CRL::try_from(dto)?)
    }
}
