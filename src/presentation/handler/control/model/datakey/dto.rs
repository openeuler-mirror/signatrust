use crate::domain::datakey::entity::{DataKey, KeyState};
use crate::domain::datakey::entity::KeyType;
use crate::util::error::Result;
use chrono::{DateTime, Utc};
use std::str::FromStr;
use crate::util::key::sorted_map;

use validator::{Validate, ValidationError};
use std::collections::HashMap;
use crate::util::error::Error;
use serde::{Deserialize, Serialize};
use utoipa::{ToSchema};
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

#[derive(Debug, Validate, Deserialize, Serialize, ToSchema)]
pub struct DataKeyDTO {
    /// Key ID, leave empty when creating
    #[serde(skip_deserializing)]
    pub id: i32,
    /// Key Name, should be identical, length between 4 and 20
    #[validate(length(min = 4, max = 20))]
    pub name: String,
    #[serde(skip_deserializing)]
    /// User email, will be removed
    pub email: String,
    /// Description, length between 0 and 100
    #[validate(length(min = 0, max = 100))]
    pub description: String,
    /// User ID, leave empty when creating
    #[serde(skip_deserializing)]
    pub user: i32,
    /// Attributes in map
    #[serde(serialize_with = "sorted_map")]
    pub attributes: HashMap<String, String>,
    /// Key type current support pgp and x509
    pub key_type: String,
    /// Fingerprint, leave empty when creating
    #[serde(skip_deserializing)]
    pub fingerprint: String,
    /// Create utc time, format: 2023-04-08 13:36:35.328324 UTC
    #[validate(custom = "validate_utc_time")]
    pub create_at: String,
    /// Expire utc time, format: 2023-04-08 13:36:35.328324 UTC
    #[validate(custom = "validate_utc_time")]
    pub expire_at: String,
    /// Key state, leave empty when creating
    #[serde(skip_deserializing)]
    pub key_state: String,
}

fn validate_utc_time(expire: &str) -> std::result::Result<(), ValidationError> {
    if expire.parse::<DateTime<Utc>>().is_err() {
        return Err(ValidationError::new("failed to parse time string to utc"));
    }
    Ok(())
}

impl DataKey {
    pub fn convert_from(dto: DataKeyDTO, identity: UserIdentity) -> Result<Self> {
        let mut combined_attributes = dto.attributes.clone();
        combined_attributes.insert("name".to_string(), dto.name.clone());
        combined_attributes.insert("create_at".to_string(), dto.create_at.clone());
        combined_attributes.insert("expire_at".to_string(), dto.expire_at.clone());
        Ok(DataKey {
            id: dto.id,
            name: dto.name,
            description: dto.description,
            user: identity.id,
            email: identity.email,
            attributes: combined_attributes,
            key_type: KeyType::from_str(dto.key_type.as_str())?,
            fingerprint: "".to_string(),
            private_key: vec![],
            public_key: vec![],
            certificate: vec![],
            create_at: dto.create_at.parse()?,
            expire_at: dto.expire_at.parse()?,
            soft_delete: false,
            key_state: KeyState::default()
        })
    }
}

impl TryFrom<DataKey> for DataKeyDTO {
    type Error = Error;

    fn try_from(dto: DataKey) -> Result<Self> {
        Ok(DataKeyDTO {
            id: dto.id,
            name: dto.name,
            description: dto.description,
            user: dto.user,
            email: dto.email,
            attributes: dto.attributes,
            key_type: dto.key_type.to_string(),
            fingerprint: dto.fingerprint,
            create_at: dto.create_at.to_string(),
            expire_at: dto.expire_at.to_string(),
            key_state: dto.key_state.to_string(),
        })
    }
}
