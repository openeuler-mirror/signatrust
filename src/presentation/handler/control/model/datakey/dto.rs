use crate::domain::datakey::entity::{DataKey, KeyState, Visibility};
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
pub struct ExportKey {
    pub public_key: String,
    pub certificate: String,
}

impl TryFrom<DataKey> for ExportKey {
    type Error = Error;

    fn try_from(value: DataKey) -> std::result::Result<Self, Self::Error> {
        Ok(ExportKey{
            public_key: String::from_utf8_lossy(&value.public_key).to_string(),
            certificate: String::from_utf8_lossy(&value.certificate).to_string()
        })
    }
}

#[derive(Deserialize, IntoParams, Validate, ToSchema)]
pub struct KeyQuery {
    /// The key's visibility
    #[validate(custom = "validate_key_visibility")]
    pub visibility: String,
}

#[derive(Deserialize, IntoParams, Validate, ToSchema)]
pub struct NameIdenticalQuery {
    /// The key's visibility
    #[validate(custom = "validate_key_visibility")]
    pub visibility: String,
    /// Key Name, should be identical, length between 4 and 20, not contains any colon symbol.
    #[validate(length(min = 4, max = 20), custom = "validate_invalid_character")]
    pub name: String,
}

impl NameIdenticalQuery {
    pub fn get_key_name(&self, user_id: &UserIdentity) -> String {
        if self.visibility == Visibility::Public.to_string() {
            self.name.clone()
        } else {
            format!("{}:{}", user_id.email, self.name)
        }

    }
}

#[derive(Debug, Validate, Deserialize, ToSchema)]
pub struct CreateDataKeyDTO {
    /// Key Name, should be identical, length between 4 and 20, not contains any colon symbol.
    #[validate(length(min = 4, max = 20), custom = "validate_invalid_character")]
    pub name: String,
    /// Description, length between 0 and 100
    #[validate(length(min = 0, max = 100))]
    pub description: String,
    /// The key's visibility
    #[validate(custom = "validate_key_visibility")]
    pub visibility: String,
    /// Attributes in map
    #[serde(serialize_with = "sorted_map")]
    pub attributes: HashMap<String, String>,
    /// Key type current support pgp and x509
    #[validate(custom = "validate_key_type")]
    pub key_type: String,
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
    /// The key's visibility
    #[validate(custom = "validate_key_visibility")]
    pub visibility: String,
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
    #[validate(custom = "validate_key_visibility")]
    pub visibility: String,
    /// User ID
    pub user: i32,
    /// Attributes in map
    #[serde(serialize_with = "sorted_map")]
    pub attributes: HashMap<String, String>,
    /// Key type
    pub key_type: String,
    /// Fingerprint
    pub fingerprint: String,
    /// Create utc time, format: 2023-04-08 13:36:35.328324 UTC
    pub create_at: String,
    /// Expire utc time, format: 2023-04-08 13:36:35.328324 UTC
    pub expire_at: String,
    /// Key state
    pub key_state: String,
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

fn validate_key_visibility(visibility: &str) -> std::result::Result<(), ValidationError> {
    match Visibility::from_str(visibility) {
        Ok(_) => {
            Ok(())
        }
        Err(_) => {
            Err(ValidationError::new("unsupported key visibility"))
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
            visibility: Visibility::from_str(dto.visibility.as_str())?,
            description: dto.description,
            user: identity.id,
            attributes: combined_attributes,
            key_type: KeyType::from_str(dto.key_type.as_str())?,
            fingerprint: "".to_string(),
            private_key: dto.private_key.into_bytes(),
            public_key: dto.public_key.into_bytes(),
            certificate: dto.certificate.into_bytes(),
            create_at: now,
            expire_at: now,
            key_state: KeyState::default()
        })
    }

    pub fn create_from(dto: CreateDataKeyDTO, identity: UserIdentity) -> Result<Self> {
        let now = Utc::now();
        let mut combined_attributes = dto.attributes.clone();
        combined_attributes.insert("name".to_string(), dto.name.clone());
        combined_attributes.insert("create_at".to_string(), now.clone().to_string());
        combined_attributes.insert("expire_at".to_string(), dto.expire_at.clone());
        let visibility = Visibility::from_str(dto.visibility.as_str())?;
        let mut key_name = dto.name;
        if visibility == Visibility::Private {
            key_name = format!("{}:{}", identity.email, key_name);
        }
        Ok(DataKey {
            id: 0,
            name: key_name,
            visibility,
            description: dto.description,
            user: identity.id,
            attributes: combined_attributes,
            key_type: KeyType::from_str(dto.key_type.as_str())?,
            fingerprint: "".to_string(),
            private_key: vec![],
            public_key: vec![],
            certificate: vec![],
            create_at: now,
            expire_at: dto.expire_at.parse()?,
            key_state: KeyState::default()
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
            fingerprint: dto.fingerprint,
            create_at: dto.create_at.to_string(),
            expire_at: dto.expire_at.to_string(),
            key_state: dto.key_state.to_string(),
        })
    }
}
