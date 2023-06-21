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
    Deleted
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
            _ => Err(Error::UnsupportedTypeError(format!("unsupported data key state {}", s))),
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
            _ => Err(Error::UnsupportedTypeError(format!("unsupported data key action {}", s))),
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
            _ => Err(Error::UnsupportedTypeError(format!("unsupported data key type {}", s))),
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
    pub fn new(ca_id: i32, data: Vec<u8>, create_at: DateTime<Utc>, update_at: DateTime<Utc>) -> Self {
        X509CRL {
            id: 0,
            ca_id,
            data,
            create_at,
            update_at,
        }
    }
}

#[derive(Debug, Clone)]
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
            _ => Err(Error::UnsupportedTypeError(format!("unsupported x509 revoke reason {}", s))),
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

#[derive(Debug, Clone)]
pub struct ParentKey {
    pub name: String,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub certificate: Vec<u8>,
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct RevokedKey {
    pub id: i32,
    pub key_id: i32,
    pub ca_id: i32,
    pub reason: X509RevokeReason,
    pub create_at: DateTime<Utc>,
    pub serial_number: Option<String>
}

#[derive(Debug, Clone)]
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
    pub parent_key: Option<ParentKey>
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
            self.id,
            self.name,
            self.user,
            self.key_type,
            self.fingerprint
        )
    }
}

#[derive(Clone)]
pub struct SecParentDateKey {
    pub name: String,
    pub private_key: SecVec<u8>,
    pub public_key: SecVec<u8>,
    pub certificate: SecVec<u8>,
    pub attributes: HashMap<String, String>
}

pub struct SecDataKey {
    pub name: String,
    pub private_key: SecVec<u8>,
    pub public_key: SecVec<u8>,
    pub certificate: SecVec<u8>,
    pub identity: String,
    pub attributes: HashMap<String, String>,
    pub parent: Option<SecParentDateKey>
}

impl SecDataKey {
    pub async fn load(data_key: &DataKey, engine: &Box<dyn EncryptionEngine>) -> Result<SecDataKey> {
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
    //NOTE: We don't support private key now.
    //Private
}

impl FromStr for Visibility {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "public" => Ok(Visibility::Public),
            _ => Err(Error::UnsupportedTypeError(format!("unsupported data key visibility {}", s))),
        }
    }
}

impl Display for Visibility {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Visibility::Public => write!(f, "public"),
        }
    }
}
