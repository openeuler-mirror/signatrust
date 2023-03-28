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
    pub expire_at: chrono::DateTime<chrono::Utc>,
}

impl From<ClusterKeyDTO> for ClusterKey {
    fn from(dto: ClusterKeyDTO) -> Self {
        ClusterKey {
            id: dto.id,
            data: dto.data,
            algorithm: dto.algorithm,
            identity: dto.identity,
            create_at: dto.create_at,
            expire_at: dto.expire_at,
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
            expire_at: cluster_key.expire_at,
        }
    }
}
