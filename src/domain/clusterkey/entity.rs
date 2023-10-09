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
use chrono::{DateTime, Utc};
use secstr::SecVec;
use std::fmt::{Display, Formatter};
use std::vec::Vec;

use crate::domain::kms_provider::KMSProvider;

#[derive(Debug, PartialEq)]
pub struct ClusterKey {
    pub id: i32,
    pub data: Vec<u8>,
    pub algorithm: String,
    pub identity: String,
    pub create_at: DateTime<Utc>,
}

impl Default for ClusterKey {
    fn default() -> Self {
        ClusterKey {
            id: 0,
            data: vec![0, 0, 0, 0],
            algorithm: "".to_string(),
            identity: "".to_string(),
            create_at: Default::default(),
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
    pub fn new(data: Vec<u8>, algorithm: String) -> Result<Self> {
        let now = Utc::now();
        let identity = format!("{}-{}", algorithm, now.format("%d-%m-%Y"));
        Ok(ClusterKey {
            id: 0,
            data,
            algorithm,
            identity,
            create_at: now,
        })
    }
}

#[derive(Clone)]
pub struct SecClusterKey {
    pub id: i32,
    pub data: SecVec<u8>,
    pub algorithm: String,
    pub identity: String,
    pub create_at: DateTime<Utc>,
}

impl Default for SecClusterKey {
    fn default() -> Self {
        SecClusterKey {
            id: 0,
            data: SecVec::new(vec![0, 0, 0, 0]),
            algorithm: "".to_string(),
            identity: "".to_string(),
            create_at: Default::default(),
        }
    }
}

impl SecClusterKey {
    pub async fn load<K>(cluster_key: ClusterKey, kms_provider: &Box<K>) -> Result<SecClusterKey>
    where
        K: KMSProvider + ?Sized,
    {
        Ok(Self {
            id: cluster_key.id,
            data: SecVec::new(key::decode_hex_string_to_u8(
                &kms_provider
                    .decode(String::from_utf8(cluster_key.data)?)
                    .await?,
            )),
            identity: cluster_key.identity,
            algorithm: cluster_key.algorithm,
            create_at: cluster_key.create_at,
        })
    }
}

impl Display for SecClusterKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id: {}, data: ******, algorithm: {} create_at: {}",
            self.id, self.algorithm, self.create_at
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::infra::kms::dummy::DummyKMS;
    use std::collections::HashMap;

    fn get_dummy_kms_provider() -> Box<dyn KMSProvider> {
        Box::new(DummyKMS::new(&HashMap::new()).unwrap())
    }

    #[tokio::test]
    async fn test_sec_cluster_key_load_and_display() {
        let kms_provider = get_dummy_kms_provider();
        let content = vec![1, 2, 3, 4];
        let hexed_content = key::encode_u8_to_hex_string(&content).as_bytes().to_vec();
        let cluster_key = ClusterKey::new(hexed_content, "FAKE_ALGORITHM".to_string())
            .expect("create cluster key failed");
        let sec_cluster_key = SecClusterKey::load(cluster_key, &kms_provider)
            .await
            .expect("load cluster key failed");
        assert_eq!(sec_cluster_key.data.unsecure(), content);
        assert_eq!(
            true,
            format!("{}", sec_cluster_key).contains("FAKE_ALGORITHM")
        );
    }

    #[test]
    fn test_sec_cluster_key_default() {
        let sec_cluster_key = SecClusterKey::default();
        assert_eq!(sec_cluster_key.id, 0);
        assert_eq!(sec_cluster_key.data.unsecure(), vec![0, 0, 0, 0]);
        assert_eq!(sec_cluster_key.algorithm, "");
        assert_eq!(sec_cluster_key.identity, "");
    }

    #[test]
    fn test_cluster_key_default() {
        let cluster_key = ClusterKey::default();
        assert_eq!(cluster_key.id, 0);
        assert_eq!(cluster_key.data, vec![0, 0, 0, 0]);
        assert_eq!(cluster_key.algorithm, "");
        assert_eq!(cluster_key.identity, "");
    }

    #[tokio::test]
    async fn test_cluster_key_new_and_display() {
        let content = vec![1, 2, 3, 4];
        let hexed_content = key::encode_u8_to_hex_string(&content).as_bytes().to_vec();
        let cluster_key = ClusterKey::new(hexed_content.clone(), "FAKE_ALGORITHM".to_string())
            .expect("create cluster key failed");
        assert_eq!(cluster_key.data, hexed_content);
        assert_eq!(true, format!("{}", cluster_key).contains("FAKE_ALGORITHM"));
    }
}
