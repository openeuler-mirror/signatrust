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
use crate::domain::datakey::entity::{DataKey, KeyState};
use crate::domain::datakey::repository::Repository;
use crate::util::error::{Result};
use async_trait::async_trait;
use std::boxed::Box;

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
}

#[async_trait]
impl Repository for DataKeyRepository {
    async fn create(&self, data_key: DataKey) -> Result<DataKey> {
        let dto = DataKeyDTO::try_from(data_key)?;
        let record : u64 = sqlx::query("INSERT INTO data_key(name, description, user, email, attributes, key_type, fingerprint, private_key, public_key, certificate, create_at, expire_at, key_state, soft_delete) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(&dto.name)
            .bind(&dto.description)
            .bind(&dto.user)
            .bind(dto.email)
            .bind(dto.attributes)
            .bind(dto.key_type)
            .bind(dto.fingerprint)
            .bind(dto.private_key)
            .bind(dto.public_key)
            .bind(dto.certificate)
            .bind(dto.create_at)
            .bind(dto.expire_at)
            .bind(dto.key_state)
            .bind(dto.soft_delete)
            .execute(&self.db_pool)
            .await?.last_insert_id();
        return self.get_by_id(record as i32).await
    }

    async fn get_all(&self) -> Result<Vec<DataKey>> {
        let dtos: Vec<DataKeyDTO> = sqlx::query_as("SELECT * FROM data_key WHERE soft_delete = ?")
            .bind(false)
            .fetch_all(&self.db_pool)
            .await?;
        let mut results = vec![];
        for dto in dtos.into_iter() {
            results.push(DataKey::try_from(dto)?);
        }
        Ok(results)
    }

    async fn get_by_id(&self, id: i32) -> Result<DataKey> {
        let dto: DataKeyDTO = sqlx::query_as("SELECT * FROM data_key WHERE id = ? AND soft_delete = ?")
            .bind(id)
            .bind(false)
            .fetch_one(&self.db_pool)
            .await?;
        Ok(DataKey::try_from(dto)?)
    }

    async fn update_state(&self, id: i32, state: KeyState) -> Result<()> {
        let _: Option<DataKeyDTO>  = sqlx::query_as("UPDATE data_key SET key_state = ? WHERE id = ? AND soft_delete = ?")
            .bind(state.to_string())
            .bind(id)
            .bind(false)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(())
    }

    async fn get_enabled_key_by_type_and_name(&self, key_type: String, name: String) -> Result<DataKey> {
        let dto: DataKeyDTO = sqlx::query_as("SELECT * FROM data_key WHERE name = ? AND key_type = ? AND key_state = ? AND soft_delete = ?")
            .bind(name)
            .bind(key_type)
            .bind(KeyState::Enabled.to_string())
            .bind(false)
            .fetch_one(&self.db_pool)
            .await?;
        Ok(DataKey::try_from(dto)?)
    }

    async fn delete_by_id(&self, id: i32) -> Result<()> {
        let _: Option<DataKeyDTO> = sqlx::query_as("UPDATE data_key SET soft_delete = ? WHERE id = ?")
            .bind(true)
            .bind(id)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(())
    }
}
