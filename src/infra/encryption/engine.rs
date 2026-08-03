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

use crate::domain::clusterkey::entity::{ClusterKey, SecClusterKey};
use crate::domain::clusterkey::repository::Repository as ClusterKeyRepository;
use crate::domain::encryption_engine::EncryptionEngine;
use crate::domain::encryptor::Encryptor;
use crate::util::error::{Error, Result};
use crate::util::key;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use config::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::kms_provider::KMSProvider;

pub const KEY_SIZE: usize = 2;
pub const DEFAULT_ROTATE_IN_DAYS: i64 = 90;
pub struct EncryptionEngineWithClusterKey<C, K, E>
where
    C: ClusterKeyRepository,
    K: KMSProvider + ?Sized,
    E: Encryptor + ?Sized,
{
    //cluster key repository
    cluster_repository: C,
    kms_provider: Box<K>,
    encryptor: Box<E>,
    rotate_in_days: i64,
    latest_cluster_key: Arc<RwLock<SecClusterKey>>,
    cluster_key_container: Arc<RwLock<HashMap<i32, SecClusterKey>>>, // cluster key id -> cluster key
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
    E: Encryptor + ?Sized,
{
    pub fn new(
        cluster_repository: C,
        encryptor: Box<E>,
        config: &HashMap<String, Value>,
        kms_provider: Box<K>,
    ) -> Result<Self> {
        let rotate_in_days = config
            .get("rotate_in_days")
            .expect("rotate in days should configured")
            .to_string()
            .parse()
            .unwrap_or(DEFAULT_ROTATE_IN_DAYS);
        if rotate_in_days < DEFAULT_ROTATE_IN_DAYS {
            return Err(Error::ConfigError(format!(
                "rotate in days should greater than {}",
                rotate_in_days
            )));
        }
        info!("cluster key will be rotated in {} days", rotate_in_days);
        Ok(EncryptionEngineWithClusterKey {
            cluster_repository,
            encryptor,
            rotate_in_days,
            latest_cluster_key: Arc::new(RwLock::new(SecClusterKey::default())),
            kms_provider,
            cluster_key_container: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    async fn append_cluster_key_hex(&self, data: &mut Vec<u8>) -> Vec<u8> {
        let mut result = vec![];
        result.append(&mut key::decode_hex_string_to_u8(&format!(
            "{:04X}",
            self.latest_cluster_key.read().await.id,
        )));
        result.append(data);
        result
    }

    async fn get_used_sec_cluster_key(&self, data: &[u8]) -> Result<SecClusterKey> {
        //convert the cluster back and obtain from database, hard code here.
        let cluster_id: i32 = (data[0] as i32) * 256 + data[1] as i32;
        if let Some(cluster_key) = self.cluster_key_container.read().await.get(&cluster_id) {
            return Ok((*cluster_key).clone());
        }
        let cluster_key = SecClusterKey::load(
            self.cluster_repository.get_by_id(cluster_id).await?,
            &self.kms_provider,
        )
        .await?;
        self.cluster_key_container
            .write()
            .await
            .insert(cluster_id, cluster_key.clone());
        Ok(cluster_key)
    }

    async fn generate_new_key(&self) -> Result<()> {
        //generate new key identified with date time
        let cluster_key = ClusterKey::new(
            self.kms_provider
                .encode(key::encode_u8_to_hex_string(&self.encryptor.generate_key()))
                .await?
                .as_bytes()
                .to_vec(),
            self.encryptor.algorithm().to_string(),
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
            Some(cluster) => {
                *self.latest_cluster_key.write().await =
                    SecClusterKey::load(cluster, &self.kms_provider).await?
            }
        };
        Ok(())
    }
}

#[async_trait]
impl<C, K, E> EncryptionEngine for EncryptionEngineWithClusterKey<C, K, E>
where
    C: ClusterKeyRepository,
    K: KMSProvider + ?Sized,
    E: Encryptor + ?Sized,
{
    async fn initialize(&mut self) -> Result<()> {
        //generate new cluster keys only when there is no db record match the date
        let key = self
            .cluster_repository
            .get_latest(&self.encryptor.algorithm().to_string())
            .await?;
        match key {
            Some(k) => {
                *self.latest_cluster_key.write().await =
                    SecClusterKey::load(k, &self.kms_provider).await?
            }
            None => {
                self.generate_new_key().await?;
            }
        }
        info!(
            "cluster key is found or generated : {}",
            self.latest_cluster_key.read().await
        );
        Ok(())
    }

    async fn rotate_key(&mut self) -> Result<bool> {
        if Utc::now()
            < self.latest_cluster_key.read().await.create_at + Duration::days(self.rotate_in_days)
        {
            return Ok(false);
        }
        self.generate_new_key().await?;
        info!(
            "cluster key is rotated : {}",
            self.latest_cluster_key.read().await
        );
        Ok(true)
    }

    async fn encode(&self, content: Vec<u8>) -> Result<Vec<u8>> {
        if content.is_empty() {
            return Ok(content);
        }
        //always use latest cluster key to encode data
        let mut secret = self.encryptor.encrypt(
            self.latest_cluster_key
                .read()
                .await
                .data
                .unsecure()
                .to_owned(),
            content,
        )?;
        Ok(self.append_cluster_key_hex(&mut secret).await)
    }

    async fn decode(&self, content: Vec<u8>) -> Result<Vec<u8>> {
        if content.is_empty() {
            return Ok(content);
        }
        //1. obtain cluster key id from content
        //2. use cluster key to decrypt data
        let sec_cluster_key = self.get_used_sec_cluster_key(&content[0..KEY_SIZE]).await?;
        self.encryptor.decrypt(
            sec_cluster_key.data.unsecure().to_owned(),
            content[KEY_SIZE..].to_vec(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::clusterkey::entity::ClusterKey;
    use crate::domain::clusterkey::repository::Repository;
    use crate::infra::encryption::algorithm::aes::Aes256GcmEncryptor;
    use crate::infra::kms::dummy::DummyKMS;
    use std::sync::Mutex;

    /// In-memory mock of ClusterKeyRepository for unit testing the engine.
    struct MockClusterKeyRepo {
        keys: Mutex<Vec<ClusterKey>>,
    }

    impl MockClusterKeyRepo {
        fn new() -> Self {
            MockClusterKeyRepo {
                keys: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl Repository for MockClusterKeyRepo {
        async fn create(&self, cluster_key: ClusterKey) -> Result<()> {
            let mut keys = self.keys.lock().unwrap();
            let new_id = keys.len() as i32 + 1;
            let mut stored = cluster_key;
            stored.id = new_id;
            keys.push(stored);
            Ok(())
        }

        async fn get_latest(&self, _algorithm: &str) -> Result<Option<ClusterKey>> {
            let keys = self.keys.lock().unwrap();
            Ok(keys.last().cloned())
        }

        async fn get_by_id(&self, id: i32) -> Result<ClusterKey> {
            let keys = self.keys.lock().unwrap();
            keys.iter()
                .find(|k| k.id == id)
                .cloned()
                .ok_or(Error::NotFoundError)
        }

        async fn delete_by_id(&self, _id: i32) -> Result<()> {
            Ok(())
        }
    }

    type TestEngine =
        EncryptionEngineWithClusterKey<MockClusterKeyRepo, DummyKMS, Aes256GcmEncryptor>;

    fn make_engine() -> TestEngine {
        let repo = MockClusterKeyRepo::new();
        let kms = Box::new(DummyKMS::new(&HashMap::new()).unwrap());
        let encryptor = Box::<Aes256GcmEncryptor>::default();
        let mut config = HashMap::new();
        config.insert("rotate_in_days".to_string(), config::Value::from("180"));
        EncryptionEngineWithClusterKey::new(repo, encryptor, &config, kms)
            .expect("create engine should succeed")
    }

    // ========== Config ==========

    #[test]
    fn test_new_engine_invalid_rotate_days() {
        let repo = MockClusterKeyRepo::new();
        let kms = Box::new(DummyKMS::new(&HashMap::new()).unwrap());
        let encryptor = Box::<Aes256GcmEncryptor>::default();
        let mut config = HashMap::new();
        config.insert(
            "rotate_in_days".to_string(),
            config::Value::from("30"), // < 90 → rejected
        );
        let result: Result<TestEngine> =
            EncryptionEngineWithClusterKey::new(repo, encryptor, &config, kms);
        assert!(result.is_err());
        let err_str = result.err().unwrap().to_string();
        assert!(
            err_str.contains("rotate in days"),
            "unexpected error: {}",
            err_str
        );
    }

    #[test]
    fn test_new_engine_valid_rotate_days() {
        let repo = MockClusterKeyRepo::new();
        let kms = Box::new(DummyKMS::new(&HashMap::new()).unwrap());
        let encryptor = Box::<Aes256GcmEncryptor>::default();
        let mut config = HashMap::new();
        config.insert("rotate_in_days".to_string(), config::Value::from("180"));
        let result: Result<TestEngine> =
            EncryptionEngineWithClusterKey::new(repo, encryptor, &config, kms);
        assert!(result.is_ok());
    }

    // ========== Key ID encoding ==========

    #[tokio::test]
    async fn test_append_cluster_key_hex_key_id_1() {
        let mut engine = make_engine();
        engine.initialize().await.unwrap();

        let mut data = vec![0xAB, 0xCD];
        let result = engine.append_cluster_key_hex(&mut data).await;
        // Key ID = 1 → hex "0001" → [0x00, 0x01]
        assert_eq!(result[0], 0x00);
        assert_eq!(result[1], 0x01);
        assert_eq!(&result[2..], &[0xAB, 0xCD]);
    }

    #[test]
    fn test_key_id_byte_encoding_format() {
        // Verify the {:04X} format produces correct byte pairs
        // Key ID 10 = 0x000A = [0x00, 0x0A]
        let hex = format!("{:04X}", 10i32);
        assert_eq!(hex, "000A");
        let bytes = key::decode_hex_string_to_u8(&hex);
        assert_eq!(bytes, vec![0x00, 0x0A]);

        // Key ID 256 = 0x0100 = [0x01, 0x00]
        let hex = format!("{:04X}", 256i32);
        assert_eq!(hex, "0100");
        let bytes = key::decode_hex_string_to_u8(&hex);
        assert_eq!(bytes, vec![0x01, 0x00]);

        // Key ID 65535 = 0xFFFF
        let hex = format!("{:04X}", 65535i32);
        assert_eq!(hex, "FFFF");
        let bytes = key::decode_hex_string_to_u8(&hex);
        assert_eq!(bytes, vec![0xFF, 0xFF]);
    }

    // ========== Empty content ==========

    #[tokio::test]
    async fn test_encode_empty_content_passthrough() {
        let mut engine = make_engine();
        engine.initialize().await.unwrap();

        let result = engine.encode(vec![]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_decode_empty_content_passthrough() {
        let engine = make_engine();
        // Decode does not need initialize for empty content
        let result = engine.decode(vec![]).await.unwrap();
        assert!(result.is_empty());
    }

    // ========== Encode/decode roundtrip ==========

    #[tokio::test]
    async fn test_encode_decode_roundtrip() {
        let mut engine = make_engine();
        engine.initialize().await.unwrap();

        let original = b"hello world, this is a test message for roundtrip encryption".to_vec();
        let encrypted = engine.encode(original.clone()).await.unwrap();

        // Encrypted data should differ from original
        assert_ne!(encrypted, original);
        // Should have at least KEY_SIZE bytes for the key ID header
        assert!(encrypted.len() > KEY_SIZE);

        let decrypted = engine.decode(encrypted).await.unwrap();
        assert_eq!(decrypted, original);
    }

    #[tokio::test]
    async fn test_encode_decode_empty() {
        let mut engine = make_engine();
        engine.initialize().await.unwrap();

        let result = engine.encode(vec![]).await.unwrap();
        assert!(result.is_empty());

        let result = engine.decode(vec![]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_encode_different_inputs_produce_different_outputs() {
        let mut engine = make_engine();
        engine.initialize().await.unwrap();

        let e1 = engine.encode(b"message one".to_vec()).await.unwrap();
        let e2 = engine.encode(b"message two".to_vec()).await.unwrap();

        // Same key ID prefix (both use same cluster key)
        assert_eq!(&e1[0..KEY_SIZE], &e2[0..KEY_SIZE]);
        // But different ciphertext
        assert_ne!(&e1[KEY_SIZE..], &e2[KEY_SIZE..]);
    }

    #[tokio::test]
    async fn test_rotate_key_returns_false_before_rotate_period() {
        let mut engine = make_engine();
        engine.initialize().await.unwrap();

        // rotate_in_days = 180, key just created → should return false
        let rotated = engine.rotate_key().await.unwrap();
        assert!(!rotated);
    }

    #[tokio::test]
    async fn test_initialize_finds_existing_key() {
        let mut engine = make_engine();
        // First init creates a key
        engine.initialize().await.unwrap();

        // Re-initialize should find the existing key, not panic
        engine.initialize().await.unwrap();
    }
}
