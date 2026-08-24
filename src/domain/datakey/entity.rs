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

use crate::domain::datakey::traits::{ExtendableAttributes, Identity};
use crate::util::error::{Error, Result};
use chrono::{DateTime, Utc};
use secstr::SecVec;
use serde_json;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::domain::encryption_engine::EncryptionEngine;

pub const INFRA_CONFIG_DOMAIN_NAME: &str = "domain_name";

#[derive(Debug, Clone, Default, PartialEq)]
pub enum KeyState {
    Enabled,
    #[default]
    Disabled,
    PendingRevoke,
    Revoked,
    PendingDelete,
    Deleted,
}

impl FromStr for KeyState {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "enabled" => Ok(KeyState::Enabled),
            "disabled" => Ok(KeyState::Disabled),
            "pending_revoke" => Ok(KeyState::PendingRevoke),
            "revoked" => Ok(KeyState::Revoked),
            "pending_delete" => Ok(KeyState::PendingDelete),
            "deleted" => Ok(KeyState::Deleted),
            _ => Err(Error::UnsupportedTypeError(format!(
                "unsupported data key state {}",
                s
            ))),
        }
    }
}

impl Display for KeyState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            KeyState::Enabled => write!(f, "enabled"),
            KeyState::Disabled => write!(f, "disabled"),
            KeyState::PendingRevoke => write!(f, "pending_revoke"),
            KeyState::Revoked => write!(f, "revoked"),
            KeyState::PendingDelete => write!(f, "pending_delete"),
            KeyState::Deleted => write!(f, "deleted"),
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum KeyAction {
    Revoke,
    CancelRevoke,
    Delete,
    CancelDelete,
    Disable,
    Enable,
    IssueCert,
    Sign,
    Read,
}

impl FromStr for KeyAction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "revoke" => Ok(KeyAction::Revoke),
            "cancel_revoke" => Ok(KeyAction::CancelRevoke),
            "delete" => Ok(KeyAction::Delete),
            "cancel_delete" => Ok(KeyAction::CancelDelete),
            "disable" => Ok(KeyAction::Disable),
            "enable" => Ok(KeyAction::Enable),
            "issue_cert" => Ok(KeyAction::IssueCert),
            "sign" => Ok(KeyAction::Sign),
            "read" => Ok(KeyAction::Read),
            _ => Err(Error::UnsupportedTypeError(format!(
                "unsupported data key action {}",
                s
            ))),
        }
    }
}

impl Display for KeyAction {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            KeyAction::Revoke => write!(f, "revoke"),
            KeyAction::CancelRevoke => write!(f, "cancel_revoke"),
            KeyAction::Delete => write!(f, "delete"),
            KeyAction::CancelDelete => write!(f, "cancel_delete"),
            KeyAction::Disable => write!(f, "disable"),
            KeyAction::Enable => write!(f, "enable"),
            KeyAction::IssueCert => write!(f, "issue_cert"),
            KeyAction::Read => write!(f, "read"),
            KeyAction::Sign => write!(f, "sign"),
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum KeyType {
    OpenPGP,
    // X509 Certificate Authority
    X509CA,
    // X509 Intermediate Certificate Authority
    X509ICA,
    // X509 End Entity
    X509EE,
}

impl FromStr for KeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "pgp" => Ok(KeyType::OpenPGP),
            "x509ca" => Ok(KeyType::X509CA),
            "x509ica" => Ok(KeyType::X509ICA),
            "x509ee" => Ok(KeyType::X509EE),
            _ => Err(Error::UnsupportedTypeError(format!(
                "unsupported data key type {}",
                s
            ))),
        }
    }
}

impl Display for KeyType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            KeyType::OpenPGP => write!(f, "pgp"),
            KeyType::X509CA => write!(f, "x509ca"),
            KeyType::X509ICA => write!(f, "x509ica"),
            KeyType::X509EE => write!(f, "x509ee"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct X509CRL {
    pub id: i32,
    pub ca_id: i32,
    pub data: Vec<u8>,
    pub create_at: DateTime<Utc>,
    pub update_at: DateTime<Utc>,
}

impl X509CRL {
    pub fn new(
        ca_id: i32,
        data: Vec<u8>,
        create_at: DateTime<Utc>,
        update_at: DateTime<Utc>,
    ) -> Self {
        X509CRL {
            id: 0,
            ca_id,
            data,
            create_at,
            update_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum X509RevokeReason {
    Unspecified,
    KeyCompromise,
    CACompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    PrivilegeWithdrawn,
    AACompromise,
}

impl FromStr for X509RevokeReason {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "unspecified" => Ok(X509RevokeReason::Unspecified),
            "key_compromise" => Ok(X509RevokeReason::KeyCompromise),
            "ca_compromise" => Ok(X509RevokeReason::CACompromise),
            "affiliation_changed" => Ok(X509RevokeReason::AffiliationChanged),
            "superseded" => Ok(X509RevokeReason::Superseded),
            "cessation_of_operation" => Ok(X509RevokeReason::CessationOfOperation),
            "certificate_hold" => Ok(X509RevokeReason::CertificateHold),
            "privilege_withdrawn" => Ok(X509RevokeReason::PrivilegeWithdrawn),
            "aa_compromise" => Ok(X509RevokeReason::AACompromise),
            _ => Err(Error::UnsupportedTypeError(format!(
                "unsupported x509 revoke reason {}",
                s
            ))),
        }
    }
}

impl Display for X509RevokeReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            X509RevokeReason::Unspecified => write!(f, "unspecified"),
            X509RevokeReason::KeyCompromise => write!(f, "key_compromise"),
            X509RevokeReason::CACompromise => write!(f, "ca_compromise"),
            X509RevokeReason::AffiliationChanged => write!(f, "affiliation_changed"),
            X509RevokeReason::Superseded => write!(f, "superseded"),
            X509RevokeReason::CessationOfOperation => write!(f, "cessation_of_operation"),
            X509RevokeReason::CertificateHold => write!(f, "certificate_hold"),
            X509RevokeReason::PrivilegeWithdrawn => write!(f, "privilege_withdrawn"),
            X509RevokeReason::AACompromise => write!(f, "aa_compromise"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParentKey {
    pub name: String,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub certificate: Vec<u8>,
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokedKey {
    pub id: i32,
    pub key_id: i32,
    pub ca_id: i32,
    pub reason: X509RevokeReason,
    pub create_at: DateTime<Utc>,
    pub serial_number: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DataKey {
    pub id: i32,
    pub name: String,
    pub visibility: Visibility,
    pub description: String,
    pub user: i32,
    pub attributes: HashMap<String, String>,
    pub key_type: KeyType,
    pub parent_id: Option<i32>,
    pub fingerprint: String,
    pub serial_number: Option<String>,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub certificate: Vec<u8>,
    pub create_at: DateTime<Utc>,
    pub expire_at: DateTime<Utc>,
    pub key_state: KeyState,
    pub user_email: Option<String>,
    pub request_delete_users: Option<String>,
    pub request_revoke_users: Option<String>,
    pub parent_key: Option<ParentKey>,
}
#[derive(Debug, Clone)]
pub struct PagedMeta {
    pub total_count: u64,
}
#[derive(Debug, Clone)]
pub struct PagedDatakey {
    pub data: Vec<DataKey>,
    pub meta: PagedMeta,
}

#[derive(Debug, Clone)]
pub struct DatakeyPaginationQuery {
    pub page_size: u64,
    pub page_number: u64,
    pub name: Option<String>,
    pub description: Option<String>,
    pub key_type: Option<String>,
    pub visibility: Option<String>,
}

impl ExtendableAttributes for DataKey {
    type Item = HashMap<String, String>;

    fn get_attributes(&self) -> Option<Self::Item> {
        Some(self.attributes.clone())
    }

    fn serialize_attributes(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.attributes)?)
    }
}

impl Identity for DataKey {
    fn get_identity(&self) -> String {
        format!(
            "<ID:{},Name:{},User:{},Type:{},Fingerprint:{}>",
            self.id, self.name, self.user, self.key_type, self.fingerprint
        )
    }
}

#[derive(Clone)]
pub struct SecParentDateKey {
    pub name: String,
    pub private_key: SecVec<u8>,
    pub public_key: SecVec<u8>,
    pub certificate: SecVec<u8>,
    pub attributes: HashMap<String, String>,
}

pub struct SecDataKey {
    pub name: String,
    pub private_key: SecVec<u8>,
    pub public_key: SecVec<u8>,
    pub certificate: SecVec<u8>,
    pub identity: String,
    pub attributes: HashMap<String, String>,
    pub parent: Option<SecParentDateKey>,
}

impl SecDataKey {
    pub async fn load(
        data_key: &DataKey,
        engine: &Box<dyn EncryptionEngine>,
    ) -> Result<SecDataKey> {
        let mut sec_datakey = Self {
            name: data_key.name.clone(),
            private_key: SecVec::new(engine.decode(data_key.private_key.clone()).await?),
            public_key: SecVec::new(engine.decode(data_key.public_key.clone()).await?),
            certificate: SecVec::new(engine.decode(data_key.certificate.clone()).await?),
            identity: data_key.get_identity(),
            attributes: data_key.attributes.clone(),
            parent: None,
        };
        if let Some(parent_key) = data_key.parent_key.clone() {
            let sec_parent_key = SecParentDateKey {
                name: parent_key.name,
                private_key: SecVec::new(engine.decode(parent_key.private_key).await?),
                public_key: SecVec::new(engine.decode(parent_key.public_key).await?),
                certificate: SecVec::new(engine.decode(parent_key.certificate).await?),
                attributes: parent_key.attributes,
            };
            sec_datakey.parent = Some(sec_parent_key);
        }
        Ok(sec_datakey)
    }
}

pub struct DataKeyContent {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub certificate: Vec<u8>,
    pub fingerprint: String,
    pub serial_number: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub enum Visibility {
    #[default]
    Public,
    Private,
}

impl Visibility {
    pub fn from_parameter(s: Option<String>) -> Result<Self> {
        match s {
            None => Ok(Visibility::Public),
            Some(value) => {
                if value == "public" {
                    return Ok(Visibility::Public);
                } else if value == "private" {
                    return Ok(Visibility::Private);
                }
                Err(Error::UnsupportedTypeError(format!(
                    "unsupported data key visibility {}",
                    value
                )))
            }
        }
    }
}

impl FromStr for Visibility {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "public" => Ok(Visibility::Public),
            "private" => Ok(Visibility::Private),
            _ => Err(Error::UnsupportedTypeError(format!(
                "unsupported data key visibility {}",
                s
            ))),
        }
    }
}

impl Display for Visibility {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Visibility::Public => write!(f, "public"),
            Visibility::Private => write!(f, "private"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== KeyState ==========

    #[test]
    fn test_key_state_default_is_disabled() {
        assert_eq!(KeyState::default(), KeyState::Disabled);
    }

    #[test]
    fn test_key_state_display() {
        assert_eq!(format!("{}", KeyState::Enabled), "enabled");
        assert_eq!(format!("{}", KeyState::Disabled), "disabled");
        assert_eq!(format!("{}", KeyState::PendingRevoke), "pending_revoke");
        assert_eq!(format!("{}", KeyState::Revoked), "revoked");
        assert_eq!(format!("{}", KeyState::PendingDelete), "pending_delete");
        assert_eq!(format!("{}", KeyState::Deleted), "deleted");
    }

    #[test]
    fn test_key_state_from_str_valid() {
        assert_eq!(KeyState::from_str("enabled").unwrap(), KeyState::Enabled);
        assert_eq!(KeyState::from_str("disabled").unwrap(), KeyState::Disabled);
        assert_eq!(
            KeyState::from_str("pending_revoke").unwrap(),
            KeyState::PendingRevoke
        );
        assert_eq!(KeyState::from_str("revoked").unwrap(), KeyState::Revoked);
        assert_eq!(
            KeyState::from_str("pending_delete").unwrap(),
            KeyState::PendingDelete
        );
        assert_eq!(KeyState::from_str("deleted").unwrap(), KeyState::Deleted);
    }

    #[test]
    fn test_key_state_from_str_invalid() {
        assert!(KeyState::from_str("unknown").is_err());
        assert!(KeyState::from_str("").is_err());
    }

    #[test]
    fn test_key_state_display_roundtrip() {
        for state in &[
            KeyState::Enabled,
            KeyState::Disabled,
            KeyState::PendingRevoke,
            KeyState::Revoked,
            KeyState::PendingDelete,
            KeyState::Deleted,
        ] {
            let s = format!("{}", state);
            let parsed = KeyState::from_str(&s).unwrap();
            assert_eq!(*state, parsed);
        }
    }

    // ========== KeyAction ==========

    #[test]
    fn test_key_action_display() {
        assert_eq!(format!("{}", KeyAction::Revoke), "revoke");
        assert_eq!(format!("{}", KeyAction::CancelRevoke), "cancel_revoke");
        assert_eq!(format!("{}", KeyAction::Delete), "delete");
        assert_eq!(format!("{}", KeyAction::CancelDelete), "cancel_delete");
        assert_eq!(format!("{}", KeyAction::Disable), "disable");
        assert_eq!(format!("{}", KeyAction::Enable), "enable");
        assert_eq!(format!("{}", KeyAction::IssueCert), "issue_cert");
        assert_eq!(format!("{}", KeyAction::Sign), "sign");
        assert_eq!(format!("{}", KeyAction::Read), "read");
    }

    #[test]
    fn test_key_action_from_str_valid() {
        assert_eq!(KeyAction::from_str("revoke").unwrap(), KeyAction::Revoke);
        assert_eq!(
            KeyAction::from_str("cancel_revoke").unwrap(),
            KeyAction::CancelRevoke
        );
        assert_eq!(KeyAction::from_str("delete").unwrap(), KeyAction::Delete);
        assert_eq!(
            KeyAction::from_str("cancel_delete").unwrap(),
            KeyAction::CancelDelete
        );
        assert_eq!(KeyAction::from_str("disable").unwrap(), KeyAction::Disable);
        assert_eq!(KeyAction::from_str("enable").unwrap(), KeyAction::Enable);
        assert_eq!(
            KeyAction::from_str("issue_cert").unwrap(),
            KeyAction::IssueCert
        );
        assert_eq!(KeyAction::from_str("sign").unwrap(), KeyAction::Sign);
        assert_eq!(KeyAction::from_str("read").unwrap(), KeyAction::Read);
    }

    #[test]
    fn test_key_action_from_str_invalid() {
        assert!(KeyAction::from_str("unknown_action").is_err());
    }

    #[test]
    fn test_key_action_display_roundtrip() {
        for action in &[
            KeyAction::Revoke,
            KeyAction::CancelRevoke,
            KeyAction::Delete,
            KeyAction::CancelDelete,
            KeyAction::Disable,
            KeyAction::Enable,
            KeyAction::IssueCert,
            KeyAction::Sign,
            KeyAction::Read,
        ] {
            let s = format!("{}", action);
            let parsed = KeyAction::from_str(&s).unwrap();
            assert_eq!(*action, parsed);
        }
    }

    // ========== KeyType ==========

    #[test]
    fn test_key_type_display() {
        assert_eq!(format!("{}", KeyType::OpenPGP), "pgp");
        assert_eq!(format!("{}", KeyType::X509CA), "x509ca");
        assert_eq!(format!("{}", KeyType::X509ICA), "x509ica");
        assert_eq!(format!("{}", KeyType::X509EE), "x509ee");
    }

    #[test]
    fn test_key_type_from_str_valid() {
        assert_eq!(KeyType::from_str("pgp").unwrap(), KeyType::OpenPGP);
        assert_eq!(KeyType::from_str("x509ca").unwrap(), KeyType::X509CA);
        assert_eq!(KeyType::from_str("x509ica").unwrap(), KeyType::X509ICA);
        assert_eq!(KeyType::from_str("x509ee").unwrap(), KeyType::X509EE);
    }

    #[test]
    fn test_key_type_from_str_invalid() {
        assert!(KeyType::from_str("unknown_type").is_err());
        assert!(KeyType::from_str("").is_err());
    }

    #[test]
    fn test_key_type_display_roundtrip() {
        for key_type in &[
            KeyType::OpenPGP,
            KeyType::X509CA,
            KeyType::X509ICA,
            KeyType::X509EE,
        ] {
            let s = format!("{}", key_type);
            let parsed = KeyType::from_str(&s).unwrap();
            assert_eq!(*key_type, parsed);
        }
    }

    // ========== X509RevokeReason ==========

    #[test]
    fn test_x509_revoke_reason_display() {
        assert_eq!(format!("{}", X509RevokeReason::Unspecified), "unspecified");
        assert_eq!(
            format!("{}", X509RevokeReason::KeyCompromise),
            "key_compromise"
        );
        assert_eq!(
            format!("{}", X509RevokeReason::CACompromise),
            "ca_compromise"
        );
        assert_eq!(
            format!("{}", X509RevokeReason::AffiliationChanged),
            "affiliation_changed"
        );
        assert_eq!(format!("{}", X509RevokeReason::Superseded), "superseded");
        assert_eq!(
            format!("{}", X509RevokeReason::CessationOfOperation),
            "cessation_of_operation"
        );
        assert_eq!(
            format!("{}", X509RevokeReason::CertificateHold),
            "certificate_hold"
        );
        assert_eq!(
            format!("{}", X509RevokeReason::PrivilegeWithdrawn),
            "privilege_withdrawn"
        );
        assert_eq!(
            format!("{}", X509RevokeReason::AACompromise),
            "aa_compromise"
        );
    }

    #[test]
    fn test_x509_revoke_reason_from_str_valid() {
        assert_eq!(
            X509RevokeReason::from_str("unspecified").unwrap(),
            X509RevokeReason::Unspecified
        );
        assert_eq!(
            X509RevokeReason::from_str("key_compromise").unwrap(),
            X509RevokeReason::KeyCompromise
        );
        assert_eq!(
            X509RevokeReason::from_str("ca_compromise").unwrap(),
            X509RevokeReason::CACompromise
        );
    }

    #[test]
    fn test_x509_revoke_reason_from_str_invalid() {
        assert!(X509RevokeReason::from_str("invalid_reason").is_err());
    }

    #[test]
    fn test_x509_revoke_reason_roundtrip() {
        for reason in &[
            X509RevokeReason::Unspecified,
            X509RevokeReason::KeyCompromise,
            X509RevokeReason::CACompromise,
            X509RevokeReason::AffiliationChanged,
            X509RevokeReason::Superseded,
            X509RevokeReason::CessationOfOperation,
            X509RevokeReason::CertificateHold,
            X509RevokeReason::PrivilegeWithdrawn,
            X509RevokeReason::AACompromise,
        ] {
            let s = format!("{}", reason);
            let parsed = X509RevokeReason::from_str(&s).unwrap();
            assert_eq!(*reason, parsed);
        }
    }

    // ========== Visibility ==========

    #[test]
    fn test_visibility_default_is_public() {
        assert_eq!(Visibility::default(), Visibility::Public);
    }

    #[test]
    fn test_visibility_display() {
        assert_eq!(format!("{}", Visibility::Public), "public");
        assert_eq!(format!("{}", Visibility::Private), "private");
    }

    #[test]
    fn test_visibility_from_str_valid() {
        assert_eq!(Visibility::from_str("public").unwrap(), Visibility::Public);
        assert_eq!(
            Visibility::from_str("private").unwrap(),
            Visibility::Private
        );
    }

    #[test]
    fn test_visibility_from_str_invalid() {
        assert!(Visibility::from_str("secret").is_err());
    }

    #[test]
    fn test_visibility_from_parameter_none() {
        assert_eq!(
            Visibility::from_parameter(None).unwrap(),
            Visibility::Public
        );
    }

    #[test]
    fn test_visibility_from_parameter_public() {
        assert_eq!(
            Visibility::from_parameter(Some("public".to_string())).unwrap(),
            Visibility::Public
        );
    }

    #[test]
    fn test_visibility_from_parameter_private() {
        assert_eq!(
            Visibility::from_parameter(Some("private".to_string())).unwrap(),
            Visibility::Private
        );
    }

    #[test]
    fn test_visibility_from_parameter_invalid() {
        assert!(Visibility::from_parameter(Some("secret".to_string())).is_err());
    }

    // ========== X509CRL ==========

    #[test]
    fn test_x509_crl_new() {
        let now = Utc::now();
        let data = vec![1, 2, 3, 4];
        let crl = X509CRL::new(42, data.clone(), now, now);
        assert_eq!(crl.id, 0);
        assert_eq!(crl.ca_id, 42);
        assert_eq!(crl.data, data);
        assert_eq!(crl.create_at, now);
        assert_eq!(crl.update_at, now);
    }

    // ========== DataKey identity ==========

    #[test]
    fn test_data_key_get_identity() {
        let key = DataKey {
            id: 1,
            name: "test-key".to_string(),
            visibility: Visibility::Public,
            description: "".to_string(),
            user: 42,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: None,
            fingerprint: "ABCD1234".to_string(),
            serial_number: None,
            private_key: vec![],
            public_key: vec![],
            certificate: vec![],
            create_at: Utc::now(),
            expire_at: Utc::now(),
            key_state: KeyState::Enabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        let identity = key.get_identity();
        assert!(identity.contains("test-key"));
        assert!(identity.contains("42"));
        assert!(identity.contains("ABCD1234"));
        assert!(identity.contains("pgp"));
    }

    // ========== DatakeyPaginationQuery ==========

    #[test]
    fn test_datakey_pagination_query_defaults() {
        let query = DatakeyPaginationQuery {
            page_size: 20,
            page_number: 1,
            name: None,
            description: None,
            key_type: None,
            visibility: None,
        };
        assert_eq!(query.page_size, 20);
        assert_eq!(query.page_number, 1);
        assert!(query.name.is_none());
        assert!(query.key_type.is_none());
    }
}
