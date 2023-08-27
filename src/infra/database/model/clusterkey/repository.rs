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

use super::dto::Entity as ClusterKeyDTO;
use crate::infra::database::model::clusterkey;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, ActiveValue::Set, QueryOrder};
use crate::domain::clusterkey::entity::ClusterKey;
use crate::domain::clusterkey::repository::Repository;
use crate::util::error::{Result, Error};
use async_trait::async_trait;
use sea_orm::sea_query::OnConflict;

#[derive(Clone)]
pub struct ClusterKeyRepository {
    db_connection: DatabaseConnection,
}

impl ClusterKeyRepository {
    pub fn new(db_connection: DatabaseConnection) -> Self {
        Self {
            db_connection,
        }
    }
}

#[async_trait]
impl Repository for ClusterKeyRepository {
    async fn create(&self, cluster_key: ClusterKey) -> Result<()> {
        let cluster_key = clusterkey::dto::ActiveModel {
            data: Set(cluster_key.data),
            algorithm: Set(cluster_key.algorithm),
            identity: Set(cluster_key.identity),
            create_at: Set(cluster_key.create_at),
            ..Default::default()
        };
        //TODO: https://github.com/SeaQL/sea-orm/issues/1790
        ClusterKeyDTO::insert(cluster_key).on_conflict(OnConflict::new()
            .update_column(clusterkey::dto::Column::Id).to_owned()
        ).exec(&self.db_connection).await?;
        Ok(())
    }

    async fn get_latest(&self, algorithm: &str) -> Result<Option<ClusterKey>> {
        match ClusterKeyDTO::find().filter(
            clusterkey::dto::Column::Algorithm.eq(algorithm)
        ).order_by_desc(clusterkey::dto::Column::Id).one(
            &self.db_connection).await? {
            None => {
                Ok(None)
            }
            Some(cluster_key) => {
                Ok(Some(ClusterKey::from(cluster_key)))
            }
        }
    }

    async fn get_by_id(&self, id: i32) -> Result<ClusterKey> {
        match ClusterKeyDTO::find_by_id(id).one(&self.db_connection).await? {
             None => {
                 Err(Error::NotFoundError)
                }
                Some(cluster_key) => {
                 Ok(ClusterKey::from(cluster_key))
                }
        }
    }
    async fn delete_by_id(&self, id: i32) -> Result<()> {
        let _ = ClusterKeyDTO::delete_by_id(
            id).exec(&self.db_connection).await?;
        Ok(())
    }
}
