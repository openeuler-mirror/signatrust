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

use super::dto::ClusterKeyDTO;

use crate::infra::database::pool::DbPool;
use crate::infra::kms::kms_provider::KMSProvider;
use crate::model::clusterkey::entity::ClusterKey;
use crate::model::clusterkey::repository::Repository;
use crate::util::error::Result;
use async_trait::async_trait;
use std::boxed::Box;
use std::sync::Arc;

#[derive(Clone)]
pub struct EncryptedClusterKeyRepository {
    db_pool: DbPool,
    kms_provider: Arc<Box<dyn KMSProvider>>,
}

impl EncryptedClusterKeyRepository {
    pub fn new(db_pool: DbPool, kms_provider: Arc<Box<dyn KMSProvider>>) -> Self {
        Self {
            db_pool,
            kms_provider,
        }
    }
}

#[async_trait]
impl Repository for EncryptedClusterKeyRepository {
    async fn create(&self, cluster_key: &ClusterKey) -> Result<()> {
        let dto = ClusterKeyDTO::encrypt(cluster_key, &self.kms_provider).await?;
        let _ : Option<ClusterKeyDTO> = sqlx::query_as("INSERT IGNORE INTO cluster_key(data, algorithm, identity, create_at, expire_at) VALUES (?, ?, ?, ?, ?)")
            .bind(&dto.data)
            .bind(&dto.algorithm)
            .bind(&dto.identity)
            .bind(dto.create_at)
            .bind(dto.expire_at)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(())
    }

    async fn get_latest(&self, algorithm: &str) -> Result<Option<ClusterKey>> {
        let latest: Option<ClusterKeyDTO> = sqlx::query_as(
            "SELECT * FROM cluster_key WHERE algorithm = ? ORDER BY id DESC LIMIT 1",
        )
        .bind(algorithm)
        .fetch_optional(&self.db_pool)
        .await?;
        match latest {
            Some(l) => return Ok(Some(l.decrypt(&self.kms_provider).await?)),
            None => Ok(None),
        }
    }

    async fn get_by_id(&self, id: i32) -> Result<ClusterKey> {
        let selected: ClusterKeyDTO = sqlx::query_as("SELECT * FROM cluster_key WHERE id = ?")
            .bind(id)
            .fetch_one(&self.db_pool)
            .await?;
        Ok(selected.decrypt(&self.kms_provider).await?)
    }

    async fn delete_by_id(&self, id: i32) -> Result<()> {
        let _: Option<ClusterKeyDTO> = sqlx::query_as("DELETE FROM cluster_key where id = ?")
            .bind(id)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(())
    }
}
