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
use sqlx::FromRow;

#[derive(Debug, FromRow)]
pub(super) struct ClusterKeyDTO {
    pub id: i32,
    pub data: Vec<u8>,
    pub algorithm: String,
    pub identity: String,
    pub create_at: chrono::DateTime<chrono::Utc>,
}

impl From<ClusterKeyDTO> for ClusterKey {
    fn from(dto: ClusterKeyDTO) -> Self {
        ClusterKey {
            id: dto.id,
            data: dto.data,
            algorithm: dto.algorithm,
            identity: dto.identity,
            create_at: dto.create_at,
        }
    }
}

impl From<ClusterKey> for ClusterKeyDTO {
    fn from(cluster_key: ClusterKey) -> Self {
        Self {
            id: cluster_key.id,
            data: cluster_key.data,
            algorithm: cluster_key.algorithm,
            identity: cluster_key.identity,
            create_at: cluster_key.create_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use super::{ClusterKey,ClusterKeyDTO};

    #[test]
    fn test_cluster_key_dto_from_entity() {
        let key = ClusterKey {
            id: 1,
            data: vec![1, 2, 3],
            algorithm: "algo".to_string(),
            identity: "id".to_string(),
            create_at: Utc::now()
        };
        let create_at = key.create_at.clone();
        let dto = ClusterKeyDTO::from(key);
        assert_eq!(dto.id, 1);
        assert_eq!(dto.data, vec![1, 2, 3]);
        assert_eq!(dto.algorithm, "algo");
        assert_eq!(dto.identity, "id");
        assert_eq!(dto.create_at, create_at);
    }

    #[test]
    fn test_cluster_key_entity_from_dto() {
        let dto = ClusterKeyDTO {
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

