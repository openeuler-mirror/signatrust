use crate::domain::datakey::entity::{DataKey, KeyState, Visibility, X509CRL};
use crate::domain::datakey::entity::KeyType;
use crate::util::error::Result;
use chrono::{DateTime, Utc};
use std::str::FromStr;
use crate::util::key::sorted_map;

use validator::{Validate, ValidationError};
use std::collections::HashMap;
use crate::util::error::Error;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use crate::presentation::handler::control::model::user::dto::UserIdentity;

#[derive(Deserialize, Serialize, ToSchema)]
pub struct PublicKeyContent {
   pub(crate) content: String,
}

impl TryFrom<DataKey> for PublicKeyContent {
    type Error = Error;

    fn try_from(value: DataKey) -> std::result::Result<Self, Self::Error> {
        Ok(PublicKeyContent{
            content: String::from_utf8_lossy(&value.public_key).to_string(),
        })
    }
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct CertificateContent {
    pub(crate) content: String,
}

impl TryFrom<DataKey> for CertificateContent {
    type Error = Error;

    fn try_from(value: DataKey) -> std::result::Result<Self, Self::Error> {
        Ok(CertificateContent{
            content: String::from_utf8_lossy(&value.certificate).to_string(),
        })
    }
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct CRLContent {
    pub(crate) content: String,
}

impl TryFrom<X509CRL> for CRLContent {
    type Error = Error;

    fn try_from(value: X509CRL) -> std::result::Result<Self, Self::Error> {
        Ok(CRLContent{
            content: String::from_utf8_lossy(&value.data).to_string(),
        })
    }
}

#[derive(Deserialize, IntoParams, Validate, ToSchema)]
pub struct NameIdenticalQuery {
    /// Key Name, should be identical, length between 4 and 20, not contains any colon symbol.
    #[validate(length(min = 4, max = 20), custom = "validate_invalid_character")]
    pub name: String,
}

#[derive(Deserialize, IntoParams, Validate, ToSchema)]
pub struct ListKeyQuery {
    /// Key type, optional, should be one of x509ca, x509ica, x509ee, or pgp
    #[validate(custom = "validate_key_type")]
    pub key_type: Option<String>,
}


#[derive(Debug, Validate, Deserialize, ToSchema)]
pub struct CreateDataKeyDTO {
    /// Key Name, should be identical, length between 4 and 20, not contains any colon symbol.
    #[validate(length(min = 4, max = 20), custom = "validate_invalid_character")]
    pub name: String,
    /// Description, length between 0 and 100
    #[validate(length(min = 0, max = 100))]
    pub description: String,
    /// Attributes in map
    #[serde(serialize_with = "sorted_map")]
    pub attributes: HashMap<String, String>,
    /// Key type current support pgp and x509
    #[validate(custom = "validate_key_type")]
    pub key_type: String,
    pub parent_id: Option<i32>,
    /// Expire utc time, format: 2023-04-08 13:36:35.328324 UTC
    #[validate(custom = "validate_utc_time")]
    pub expire_at: String,
}

#[derive(Debug, Validate, Deserialize, ToSchema)]
pub struct ImportDataKeyDTO {
    /// Key Name, should be identical, length between 4 and 20, not contains any colon symbol.
    #[validate(length(min = 4, max = 20), custom = "validate_invalid_character")]
    pub name: String,
    /// Description, length between 0 and 100
    #[validate(length(min = 0, max = 100))]
    pub description: String,
    /// Attributes in map
    pub attributes: HashMap<String, String>,
    /// Key type current support pgp and x509
    #[validate(custom = "validate_key_type")]
    pub key_type: String,
    /// private key in text format
    pub private_key: String,
    /// public key in text format
    pub public_key: String,
    /// certificate in text format
    pub certificate: String,
}

#[derive(Debug, Validate, Deserialize, ToSchema)]
pub struct RevokeCertificateDTO {
    /// Revoke reason
    pub reason: String,
}

#[derive(Debug, Validate, Serialize, ToSchema)]
pub struct DataKeyDTO {
    /// Key ID
    pub id: i32,
    /// Key Name
    #[validate(length(min = 4, max = 20))]
    pub name: String,
    /// Description
    #[validate(length(min = 0, max = 100))]
    pub description: String,
    /// The key's visibility
    pub visibility: String,
    /// User ID
    pub user: i32,
    /// Attributes in map
    #[serde(serialize_with = "sorted_map")]
    pub attributes: HashMap<String, String>,
    /// Key type
    pub key_type: String,
    /// parent id, used for x509ica and x509ee
    pub parent_id: Option<i32>,
    /// Fingerprint
    pub fingerprint: String,
    /// Serial number
    pub serial_number: Option<String>,
    /// Create utc time, format: 2023-04-08 13:36:35.328324 UTC
    pub create_at: String,
    /// Expire utc time, format: 2023-04-08 13:36:35.328324 UTC
    pub expire_at: String,
    /// Key state
    pub key_state: String,
    /// User email
    pub user_email: Option<String>,
    /// Request delete user email list, only for public key
    pub request_delete_users: Option<String>,
    /// Request revoke user email list, only for public key
    pub request_revoke_users: Option<String>,
}

fn validate_utc_time(expire: &str) -> std::result::Result<(), ValidationError> {
    if expire.parse::<DateTime<Utc>>().is_err() {
        return Err(ValidationError::new("failed to parse time string to utc"));
    }
    Ok(())
}

fn validate_key_type(key_type: &str) -> std::result::Result<(), ValidationError> {
    match KeyType::from_str(key_type) {
        Ok(_) => {
            Ok(())
        }
        Err(_) => {
            Err(ValidationError::new("unsupported key type"))
        }
    }
}

fn validate_invalid_character(name: &str) -> std::result::Result<(), ValidationError> {
    if name.contains(':') {
        return Err(ValidationError::new("invalid character(':') in name"));
    }
    Ok(())
}

impl DataKey {
    pub fn import_from(dto: ImportDataKeyDTO, identity: UserIdentity) -> Result<Self> {
        let now = Utc::now();
        let mut combined_attributes = dto.attributes.clone();
        combined_attributes.insert("name".to_string(), dto.name.clone());
        combined_attributes.insert("create_at".to_string(), now.clone().to_string());
        Ok(DataKey {
            id: 0,
            name: dto.name,
            visibility: Visibility::Public,
            description: dto.description,
            user: identity.id,
            attributes: combined_attributes,
            key_type: KeyType::from_str(dto.key_type.as_str())?,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: dto.private_key.into_bytes(),
            public_key: dto.public_key.into_bytes(),
            certificate: dto.certificate.into_bytes(),
            create_at: now,
            expire_at: now,
            key_state: KeyState::default(),
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        })
    }

    pub fn create_from(dto: CreateDataKeyDTO, identity: UserIdentity) -> Result<Self> {
        let now = Utc::now();
        let mut combined_attributes = dto.attributes.clone();
        combined_attributes.insert("name".to_string(), dto.name.clone());
        combined_attributes.insert("create_at".to_string(), now.clone().to_string());
        combined_attributes.insert("expire_at".to_string(), dto.expire_at.clone());
        Ok(DataKey {
            id: 0,
            name: dto.name,
            visibility: Visibility::Public,
            description: dto.description,
            user: identity.id,
            attributes: combined_attributes,
            key_type: KeyType::from_str(dto.key_type.as_str())?,
            parent_id: dto.parent_id,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![],
            public_key: vec![],
            certificate: vec![],
            create_at: now,
            expire_at: dto.expire_at.parse()?,
            key_state: KeyState::default(),
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        })
    }
}

impl TryFrom<DataKey> for DataKeyDTO {
    type Error = Error;

    fn try_from(dto: DataKey) -> Result<Self> {
        let mut attributes = dto.attributes.clone();
        let _ = attributes.remove("passphrase");
        Ok(DataKeyDTO {
            id: dto.id,
            name: dto.name,
            description: dto.description,
            visibility: dto.visibility.to_string(),
            user: dto.user,
            attributes,
            key_type: dto.key_type.to_string(),
            parent_id: dto.parent_id,
            fingerprint: dto.fingerprint,
            serial_number: dto.serial_number,
            create_at: dto.create_at.to_string(),
            expire_at: dto.expire_at.to_string(),
            key_state: dto.key_state.to_string(),
            user_email: dto.user_email,
            request_delete_users: dto.request_delete_users,
            request_revoke_users: dto.request_revoke_users,
        })
    }
}
