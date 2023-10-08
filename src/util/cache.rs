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

use crate::domain::datakey::entity::DataKey;
use crate::domain::user::entity::User;
use crate::util::error::{Error, Result};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

const DATAKEY_EXPIRE_SECOND: i64 = 10 * 60;
const USER_EXPIRE_SECOND: i64 = 60 * 60;

#[derive(Clone)]
pub struct TimedFixedSizeCache {
    cached_keys: Arc<RwLock<HashMap<String, CachedDatakey>>>,
    cached_users: Arc<RwLock<HashMap<String, CachedUser>>>,
    key_size: Option<usize>,
    user_size: Option<usize>,
    key_expire: Option<i64>,
    user_expire: Option<i64>,
}
#[derive(Clone)]
pub struct CachedDatakey {
    time: DateTime<Utc>,
    key: DataKey,
}
#[derive(Clone)]
pub struct CachedUser {
    time: DateTime<Utc>,
    user: User,
}

impl TimedFixedSizeCache {
    pub fn new(
        key_size: Option<usize>,
        user_size: Option<usize>,
        key_expire: Option<i64>,
        user_expire: Option<i64>,
    ) -> Self {
        Self {
            cached_keys: Arc::new(RwLock::new(HashMap::new())),
            cached_users: Arc::new(RwLock::new(HashMap::new())),
            key_size,
            user_size,
            key_expire: key_expire.or(Some(DATAKEY_EXPIRE_SECOND)),
            user_expire: user_expire.or(Some(USER_EXPIRE_SECOND)),
        }
    }

    pub async fn get_user(&self, identity: &str) -> Option<User> {
        self.user_size?;
        let mut rs = None;
        if let Some(user) = self.cached_users.read().await.get(identity) {
            if Utc::now().lt(&(user.time + Duration::seconds(self.user_expire.unwrap()))) {
                rs = Some(user.user.clone())
            }
        }
        rs
    }

    pub async fn update_user(&self, identity: &str, user: User) -> Result<()> {
        if let Some(size) = self.user_size {
            if self.cached_users.read().await.len() >= size {
                self.cached_users.write().await.clear();
            }
        } else {
            return Err(Error::UnsupportedTypeError(
                "user cache not enabled".to_string(),
            ));
        }
        self.cached_users.write().await.insert(
            identity.to_owned(),
            CachedUser {
                time: Utc::now(),
                user,
            },
        );
        Ok(())
    }

    async fn get_datakey(&self, identity: &str) -> Option<DataKey> {
        self.key_size?;
        let mut rs = None;
        if let Some(dk) = self.cached_keys.read().await.get(identity) {
            if dk.time + Duration::seconds(self.key_expire.unwrap()) >= Utc::now() {
                rs = Some(dk.key.clone())
            }
        }
        rs
    }

    async fn update_datakey(&self, identity: &str, datakey: DataKey) -> Result<()> {
        if let Some(size) = self.key_size {
            if self.cached_keys.read().await.len() >= size {
                self.cached_keys.write().await.clear();
            }
        } else {
            return Err(Error::UnsupportedTypeError(
                "datakey cache not enabled".to_string(),
            ));
        }
        self.cached_keys.write().await.insert(
            identity.to_owned(),
            CachedDatakey {
                time: Utc::now(),
                key: datakey,
            },
        );
        Ok(())
    }

    pub async fn get_read_datakey(&self, id_or_name: &str) -> Option<DataKey> {
        self.get_datakey(&self.get_read_identity(id_or_name)).await
    }

    pub async fn get_sign_datakey(&self, id_or_name: &str) -> Option<DataKey> {
        self.get_datakey(&self.get_sign_identity(id_or_name)).await
    }

    pub async fn update_sign_datakey(&self, id_or_name: &str, datakey: DataKey) -> Result<()> {
        self.update_datakey(&self.get_sign_identity(id_or_name), datakey)
            .await
    }

    pub async fn update_read_datakey(&self, id_or_name: &str, datakey: DataKey) -> Result<()> {
        self.update_datakey(&self.get_read_identity(id_or_name), datakey)
            .await
    }

    fn get_sign_identity(&self, key_name: &str) -> String {
        format!("sign-{}", key_name)
    }

    fn get_read_identity(&self, key_name: &str) -> String {
        format!("read-{}", key_name)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::domain::datakey::entity::KeyType::OpenPGP;
    use crate::util::error::Result;
    use std::thread::sleep;

    #[tokio::test]
    async fn test_user_cache() -> Result<()> {
        let user_cache = TimedFixedSizeCache::new(None, Some(1), None, None);
        let user1 = User {
            id: 1,
            email: "fake_email@gmail.com".to_string(),
        };
        let user2 = User {
            id: 2,
            email: "fake_email@gmail.com".to_string(),
        };
        let identity1 = "token1";
        let identity2 = "token2";
        assert_eq!(user_cache.get_user(&identity1).await, None);
        assert_eq!(user_cache.update_user(&identity1, user1.clone()).await?, ());
        assert_eq!(user_cache.get_user(&identity1).await, Some(user1));
        assert_eq!(user_cache.update_user(&identity2, user2.clone()).await?, ());
        assert_eq!(user_cache.cached_users.read().await.len(), 1);
        assert_eq!(user_cache.get_user(&identity1).await, None);
        assert_eq!(user_cache.get_user(&identity2).await, Some(user2.clone()));

        let user_cache = TimedFixedSizeCache::new(None, None, None, None);
        assert_eq!(user_cache.get_user(&identity1).await, None);
        assert!(user_cache
            .update_user(&identity2, user2.clone())
            .await
            .is_err());

        let user_cache = TimedFixedSizeCache::new(None, Some(1), None, Some(1));
        assert_eq!(user_cache.update_user(&identity2, user2).await?, ());
        sleep(Duration::seconds(2).to_std()?);
        assert_eq!(user_cache.get_user(&identity2).await, None);
        Ok(())
    }

    #[tokio::test]
    async fn test_datakey_cache() -> Result<()> {
        let key_cache = TimedFixedSizeCache::new(Some(2), None, None, None);
        let datakey1 = DataKey {
            id: 1,
            name: "fake datakey1".to_string(),
            visibility: Default::default(),
            description: "".to_string(),
            user: 0,
            attributes: Default::default(),
            key_type: OpenPGP,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![],
            public_key: vec![],
            certificate: vec![],
            create_at: Default::default(),
            expire_at: Default::default(),
            key_state: Default::default(),
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        let datakey2 = DataKey {
            id: 2,
            name: "fake datakey2".to_string(),
            visibility: Default::default(),
            description: "".to_string(),
            user: 0,
            attributes: Default::default(),
            key_type: OpenPGP,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![],
            public_key: vec![],
            certificate: vec![],
            create_at: Default::default(),
            expire_at: Default::default(),
            key_state: Default::default(),
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        let identity1 = "datakey1";
        let identity2 = "1";
        assert_eq!(key_cache.get_read_datakey(&identity1).await, None);
        assert_eq!(
            key_cache
                .update_read_datakey(&identity1, datakey1.clone())
                .await?,
            ()
        );
        assert_eq!(
            key_cache.get_read_datakey(&identity1).await,
            Some(datakey1.clone())
        );
        assert_eq!(key_cache.get_sign_datakey(&identity1).await, None);
        assert_eq!(key_cache.get_datakey(&identity1).await, None);
        assert_eq!(
            key_cache
                .update_sign_datakey(&identity1, datakey1.clone())
                .await?,
            ()
        );
        assert_eq!(
            key_cache.get_sign_datakey(&identity1).await,
            Some(datakey1.clone())
        );
        assert_eq!(
            key_cache
                .update_sign_datakey(&identity2, datakey2.clone())
                .await?,
            ()
        );
        assert_eq!(
            key_cache.get_sign_datakey(&identity2).await,
            Some(datakey2.clone())
        );
        assert_eq!(key_cache.get_sign_datakey(&identity1).await, None);
        assert_eq!(key_cache.get_read_datakey(&identity1).await, None);

        let key_cache = TimedFixedSizeCache::new(None, None, None, None);
        assert_eq!(key_cache.get_datakey(&identity1).await, None);
        assert!(key_cache
            .update_datakey(&identity1, datakey1.clone())
            .await
            .is_err());

        let key_cache = TimedFixedSizeCache::new(Some(1), None, Some(1), Some(1));
        assert_eq!(key_cache.update_datakey(&identity1, datakey1).await?, ());
        sleep(Duration::seconds(2).to_std()?);
        assert_eq!(key_cache.get_datakey(&identity1).await, None);
        Ok(())
    }
}
