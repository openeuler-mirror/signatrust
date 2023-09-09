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


use crate::domain::clusterkey::entity::ClusterKey;

use sqlx::types::chrono;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Deserialize, Serialize)]
#[sea_orm(table_name = "cluster_key")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub data: Vec<u8>,
    pub algorithm: String,
    pub identity: String,
    pub create_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for ClusterKey {
    fn from(dto: Model) -> Self {
        ClusterKey {
            id: dto.id,
            data: dto.data,
            algorithm: dto.algorithm,
            identity: dto.identity,
            create_at: dto.create_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use super::{ClusterKey,Model};

    #[test]
    fn test_cluster_key_entity_from_dto() {
        let dto = Model {
            id: 1,
            data: vec![1, 2, 3],
            algorithm: "algo".to_string(),
            identity: "id".to_string(),
            create_at: Utc::now()
        };

        let create_at = dto.create_at.clone();
        let key = ClusterKey::from(dto);
        assert_eq!(key.id, 1);
        assert_eq!(key.data, vec![1, 2, 3]);
        assert_eq!(key.algorithm, "algo");
        assert_eq!(key.identity, "id");
        assert_eq!(key.create_at, create_at);
    }

}

