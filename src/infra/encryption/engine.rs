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

use crate::domain::encryptor::Encryptor;
use crate::domain::encryption_engine::EncryptionEngine;
use crate::domain::clusterkey::entity::{ClusterKey, SecClusterKey};
use crate::domain::clusterkey::repository::Repository as ClusterKeyRepository;
use crate::util::error::{Error, Result};
use crate::util::key;
use async_trait::async_trait;
use config::Value;
use std::collections::HashMap;

use crate::domain::kms_provider::KMSProvider;

pub const KEY_SIZE: usize = 2;

pub struct EncryptionEngineWithClusterKey<C, K, E>
where
    C: ClusterKeyRepository,
    K: KMSProvider + ?Sized,
    E: Encryptor + ?Sized
{
    //cluster key repository
    cluster_repository: C,
    kms_provider: Box<K>,
    encryptor: Box<E>,
    keep_in_days: i64,
    latest_cluster_key: Box<SecClusterKey>,
}

/// considering we have rotated cluster key for safety concern
/// we need append cluster key id to the encrypt data, for example
/// encrypted data 1 in hex string
/// 000A, AB13......BF46, A237.....BA13CC46
/// |-key id-|--nonce--|---encrypted data--|
/// 1. key id: is the cluster key used for encryption, fixed size
/// 2. nonce: the random bytes used for encryption. fixed size
/// 3. encrypted data: the encrypted content
impl<C, K, E> EncryptionEngineWithClusterKey<C, K, E>
where
    C: ClusterKeyRepository,
    K: KMSProvider + ?Sized,
    E: Encryptor + ?Sized
{
    pub fn new(
        cluster_repository: C,
        encryptor: Box<E>,
        config: &HashMap<String, Value>,
        kms_provider: Box<K>) -> Result<Self> {
        Ok(EncryptionEngineWithClusterKey {
            cluster_repository,
            encryptor,
            keep_in_days: config
                .get("keep_in_days")
                .expect("encryption engine should configured")
                .to_string()
                .parse()?,
            latest_cluster_key: Box::<SecClusterKey>::default(),
            kms_provider,

        })
    }
    fn append_cluster_key_hex(&self, data: &mut Vec<u8>) -> Vec<u8> {
        let mut result = vec![];
        result.append(&mut key::decode_hex_string_to_u8(&format!(
            "{:04X}",
            self.latest_cluster_key.id
        )));
        result.append(data);
        result
    }

    async fn get_used_sec_cluster_key(&self, data: &[u8]) -> Result<SecClusterKey> {
        //convert the cluster back and obtain from database, hard code here.
        let cluster_id: i32 = (data[0] as i32) * 256 + data[1] as i32;
        SecClusterKey::load( self.cluster_repository.get_by_id(cluster_id).await?, &self.kms_provider).await
    }
}

#[async_trait]
impl<C, K, E> EncryptionEngine for EncryptionEngineWithClusterKey<C, K, E>
where
    C: ClusterKeyRepository,
    K: KMSProvider + ?Sized,
    E: Encryptor + ?Sized
{
    async fn initialize(&mut self) -> Result<()> {
        //generate new symmetric keys when there is no db record
        let key = self
            .cluster_repository
            .get_latest(&self.encryptor.algorithm().to_string())
            .await?;
        match key {
            Some(k) => *self.latest_cluster_key = SecClusterKey::load(k, &self.kms_provider).await?,
            None => {
                let cluster_key = ClusterKey::new(
                        self.kms_provider.encode(
                            key::encode_u8_to_hex_string(&self.encryptor.generate_key()))
                        .await?.as_bytes().to_vec(),
                    self.encryptor.algorithm().to_string(),
                    self.keep_in_days,
                )?;
                //insert when no records
                self.cluster_repository.create(cluster_key).await?;
                match self
                    .cluster_repository
                    .get_latest(&self.encryptor.algorithm().to_string())
                    .await?
                {
                    None => {
                        return Err(Error::ConfigError(
                            "can't find latest cluster key from database".to_string(),
                        ))
                    }
                    Some(cluster) => *self.latest_cluster_key = SecClusterKey::load(cluster, &self.kms_provider).await?,
                }
            }
        }
        info!("current cluster key is: {}", self.latest_cluster_key);
        Ok(())
    }
    async fn encode(&self, content: Vec<u8>) -> Result<Vec<u8>> {
        //always use latest cluster key to encode data
        let mut secret = self
            .encryptor
            .encrypt(self.latest_cluster_key.data.unsecure().to_owned(), content)?;
        Ok(self.append_cluster_key_hex(&mut secret))
    }

    async fn decode(&self, content: Vec<u8>) -> Result<Vec<u8>> {
        //1. obtain cluster key id from content
        //2. use cluster key to decrypt data
        let sec_cluster_key = self.get_used_sec_cluster_key(&content[0..KEY_SIZE]).await?;
        self.encryptor.decrypt(
            sec_cluster_key.data.unsecure().to_owned(),
            content[KEY_SIZE..].to_vec(),
        )
    }
}
