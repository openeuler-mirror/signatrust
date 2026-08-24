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

use crate::domain::datakey::entity::{DataKey, KeyType};
use crate::domain::sign_plugin::SignPlugins;
use crate::infra::sign_plugin::openpgp::OpenPGPPlugin;
use crate::infra::sign_plugin::x509::X509Plugin;
use crate::util::error::Result;

use crate::domain::datakey::entity::SecDataKey;

pub struct Signers {}

impl Signers {
    //get responding sign plugin for data signing
    pub fn load_from_data_key(
        key_type: &KeyType,
        data_key: SecDataKey,
        timestamp_key: Option<SecDataKey>,
    ) -> Result<Box<dyn SignPlugins>> {
        match key_type {
            KeyType::OpenPGP => Ok(Box::new(OpenPGPPlugin::new(data_key, None)?)),
            KeyType::X509CA | KeyType::X509ICA | KeyType::X509EE => {
                Ok(Box::new(X509Plugin::new(data_key, timestamp_key)?))
            }
        }
    }

    pub fn validate_and_update(datakey: &mut DataKey) -> Result<()> {
        match datakey.key_type {
            KeyType::OpenPGP => OpenPGPPlugin::validate_and_update(datakey),
            KeyType::X509CA | KeyType::X509ICA | KeyType::X509EE => {
                X509Plugin::validate_and_update(datakey)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::datakey::entity::{KeyState, Visibility};
    use std::collections::HashMap;

    fn make_empty_sec_data_key() -> SecDataKey {
        SecDataKey {
            name: "test-key".to_string(),
            private_key: secstr::SecVec::new(vec![]),
            public_key: secstr::SecVec::new(vec![]),
            certificate: secstr::SecVec::new(vec![]),
            identity: "test-identity".to_string(),
            attributes: HashMap::new(),
            parent: None,
        }
    }

    #[test]
    fn test_load_from_data_key_openpgp_succeeds_on_construction() {
        // OpenPGPPlugin::new stores keys without upfront validation
        let sec_key = make_empty_sec_data_key();
        let result = Signers::load_from_data_key(&KeyType::OpenPGP, sec_key, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_from_data_key_x509_ca_succeeds_on_construction() {
        let sec_key = make_empty_sec_data_key();
        let result = Signers::load_from_data_key(&KeyType::X509CA, sec_key, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_from_data_key_x509_ica_succeeds_on_construction() {
        let sec_key = make_empty_sec_data_key();
        let result = Signers::load_from_data_key(&KeyType::X509ICA, sec_key, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_from_data_key_x509_ee_succeeds_on_construction() {
        let sec_key = make_empty_sec_data_key();
        let result = Signers::load_from_data_key(&KeyType::X509EE, sec_key, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_from_data_key_x509_ica_with_timestamp_key() {
        let sec_key = make_empty_sec_data_key();
        let ts_key = make_empty_sec_data_key();
        let result = Signers::load_from_data_key(&KeyType::X509ICA, sec_key, Some(ts_key));
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_from_data_key_dispatches_all_key_types() {
        // Verify dispatch works for all four key types
        for key_type in &[
            KeyType::OpenPGP,
            KeyType::X509CA,
            KeyType::X509ICA,
            KeyType::X509EE,
        ] {
            let sec_key = make_empty_sec_data_key();
            let result = Signers::load_from_data_key(key_type, sec_key, None);
            assert!(result.is_ok(), "failed to dispatch for {:?}", key_type);
        }
    }

    #[test]
    fn test_validate_and_update_dispatches_pgp() {
        let mut key = DataKey {
            id: 1,
            name: "test".to_string(),
            visibility: Visibility::Public,
            description: "".to_string(),
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![],
            public_key: vec![],
            certificate: vec![],
            create_at: chrono::Utc::now(),
            expire_at: chrono::Utc::now(),
            key_state: KeyState::Enabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        let result = Signers::validate_and_update(&mut key);
        // Empty PGP key data should fail validation
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_and_update_dispatches_x509() {
        let mut key = DataKey {
            id: 2,
            name: "test-x509".to_string(),
            visibility: Visibility::Public,
            description: "".to_string(),
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::X509CA,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![],
            public_key: vec![],
            certificate: vec![],
            create_at: chrono::Utc::now(),
            expire_at: chrono::Utc::now(),
            key_state: KeyState::Enabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        let result = Signers::validate_and_update(&mut key);
        // Empty X509 key data should fail validation
        assert!(result.is_err());
    }
}
