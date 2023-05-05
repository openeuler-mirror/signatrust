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

use crate::util::{error::Result, key};
use secstr::SecVec;
use chrono::{DateTime, Duration, Utc};
use std::fmt::{Display, Formatter};
use std::vec::Vec;

use crate::domain::kms_provider::KMSProvider;

#[derive(Debug)]
pub struct ClusterKey {
    pub id: i32,
    pub data: Vec<u8>,
    pub algorithm: String,
    pub identity: String,
    pub create_at: DateTime<Utc>,
    pub expire_at: DateTime<Utc>,
}

impl Default for ClusterKey {
    fn default() -> Self {
        ClusterKey {
            id: 0,
            data: vec![0, 0, 0, 0],
            algorithm: "".to_string(),
            identity: "".to_string(),
            create_at: Default::default(),
            expire_at: Default::default(),
        }
    }
}

impl Display for ClusterKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id: {}, data: ******, algorithm: {}",
            self.id, self.algorithm
        )
    }
}

impl ClusterKey {
    pub fn new(data: Vec<u8>, algorithm: String, keep_in_days: i64) -> Result<Self> {
        let now = Utc::now();
        let identity = format!("{}-{}", algorithm, now.format("%d-%m-%Y"));
        Ok(ClusterKey {
            id: 0,
            data,
            algorithm,
            identity,
            create_at: now,
            expire_at: now + Duration::days(keep_in_days),
        })
    }
}

#[derive(Clone)]
pub struct SecClusterKey {
    pub id: i32,
    pub data: SecVec<u8>,
    pub algorithm: String,
    pub identity: String,
}

impl Default for SecClusterKey {

    fn default() -> Self {
        SecClusterKey {
            id: 0,
            data: SecVec::new(vec![0, 0, 0, 0]),
            algorithm: "".to_string(),
            identity: "".to_string(),
        }
    }
}


impl SecClusterKey {
    pub async fn load<K>(cluster_key: ClusterKey, kms_provider: &Box<K>) -> Result<SecClusterKey>
    where K: KMSProvider + ?Sized {
        Ok(Self {
            id: cluster_key.id,
            data: SecVec::new(key::decode_hex_string_to_u8(
                &kms_provider
                    .decode(String::from_utf8(cluster_key.data)?)
                    .await?,
            )),
            identity: cluster_key.identity,
            algorithm: cluster_key.algorithm,
        })
    }
}

impl Display for SecClusterKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id: {}, data: ******, algorithm: {}",
            self.id, self.algorithm
        )
    }
}

