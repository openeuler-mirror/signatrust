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

use crate::domain::datakey::entity::KeyType;
use crate::domain::datakey::entity::{
    DataKey, DatakeyPaginationQuery, KeyState, PagedDatakey, Visibility, X509CRL,
};
use crate::util::error::Result;
use crate::util::key::{get_datakey_full_name, sorted_map};
use chrono::{DateTime, Utc};
use std::str::FromStr;

use crate::presentation::handler::control::model::user::dto::UserIdentity;
use crate::util::error::Error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::{IntoParams, ToSchema};
use validator::{Validate, ValidationError};

#[derive(Deserialize, Serialize, ToSchema)]
pub struct PublicKeyContent {
    pub(crate) content: String,
}

impl TryFrom<DataKey> for PublicKeyContent {
    type Error = Error;

    fn try_from(value: DataKey) -> std::result::Result<Self, Self::Error> {
        Ok(PublicKeyContent {
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
        Ok(CertificateContent {
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
        Ok(CRLContent {
            content: String::from_utf8_lossy(&value.data).to_string(),
        })
    }
}

#[derive(Deserialize, IntoParams, Validate, ToSchema)]
pub struct NameIdenticalQuery {
    /// Key Name, should be identical, length between 4 and 256, not contains any colon symbol.
    #[validate(length(min = 4, max = 256))]
    pub name: String,
    /// Key Name, should be identical, length between 4 and 20, not contains any colon symbol.
    #[validate(custom = "validate_key_visibility")]
    pub visibility: Option<String>,
}

#[derive(Deserialize, IntoParams, Validate, ToSchema)]
pub struct ListKeyQuery {
    /// Filter by key type, optional, x509ca, x509ica, x509ee, or pgp, exact match
    pub key_type: Option<String>,
    /// Filter by visibility, optional, public or private, exact match
    pub visibility: Option<String>,
    /// Filter by key name, fuzzy match
    pub name: Option<String>,
    /// Filter by description, fuzzy match
    pub description: Option<String>,
    /// the request page size, min 10, max 100
    #[validate(range(min = 10, max = 100))]
    pub page_size: u64,
    /// the request page index, starts from 1, max 1000
    #[validate(range(min = 1, max = 1000))]
    pub page_number: u64,
}

impl From<ListKeyQuery> for DatakeyPaginationQuery {
    fn from(value: ListKeyQuery) -> Self {
        Self {
            page_size: value.page_size,
            page_number: value.page_number,
            name: value.name,
            description: value.description,
            key_type: value.key_type,
            visibility: value.visibility,
        }
    }
}

#[derive(Debug, Validate, Deserialize, ToSchema)]
pub struct CreateDataKeyDTO {
    /// Key Name, should be identical, length between 4 and 256, not contains any colon symbol.
    #[validate(length(min = 4, max = 256), custom = "validate_invalid_character")]
    pub name: String,
    /// Description, length between 0 and 200
    #[validate(length(min = 0, max = 200))]
    pub description: String,
    /// The key's visibility
    #[validate(custom = "validate_key_visibility")]
    pub visibility: Option<String>,
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
    /// Key Name, should be identical, length between 4 and 256, not contains any colon symbol.
    #[validate(length(min = 4, max = 256), custom = "validate_invalid_character")]
    pub name: String,
    /// Description, length between 0 and 200
    #[validate(length(min = 0, max = 200))]
    pub description: String,
    /// The key's visibility
    #[validate(custom = "validate_key_visibility")]
    pub visibility: Option<String>,
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

#[derive(Debug, Serialize, ToSchema)]
pub struct PagedMetaDTO {
    pub total_count: u64,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct PagedDatakeyDTO {
    pub data: Vec<DataKeyDTO>,
    pub meta: PagedMetaDTO,
}

impl TryFrom<PagedDatakey> for PagedDatakeyDTO {
    type Error = Error;

    fn try_from(dto: PagedDatakey) -> Result<Self> {
        let mut keys = vec![];
        for k in dto.data {
            keys.push(DataKeyDTO::try_from(k)?)
        }
        Ok(Self {
            data: keys,
            meta: PagedMetaDTO {
                total_count: dto.meta.total_count,
            },
        })
    }
}

fn validate_utc_time(expire: &str) -> std::result::Result<(), ValidationError> {
    if expire.parse::<DateTime<Utc>>().is_err() {
        return Err(ValidationError::new("failed to parse time string to utc"));
    }
    Ok(())
}

fn validate_key_visibility(visibility: &str) -> std::result::Result<(), ValidationError> {
    match Visibility::from_str(visibility) {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationError::new("unsupported key visibility")),
    }
}

fn validate_key_type(key_type: &str) -> std::result::Result<(), ValidationError> {
    match KeyType::from_str(key_type) {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationError::new("unsupported key type")),
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
        let visibility = Visibility::from_parameter(dto.visibility)?;
        let key_name = get_datakey_full_name(&dto.name, &identity.email, &visibility)?;
        let mut key_state = KeyState::Disabled;
        if visibility == Visibility::Private {
            key_state = KeyState::Enabled;
        }
        Ok(DataKey {
            id: 0,
            name: key_name,
            visibility,
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
            key_state,
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
        let visibility = Visibility::from_parameter(dto.visibility)?;
        let key_name = get_datakey_full_name(&dto.name, &identity.email, &visibility)?;
        let mut key_state = KeyState::Disabled;
        if visibility == Visibility::Private {
            key_state = KeyState::Enabled;
        }
        Ok(DataKey {
            id: 0,
            name: key_name,
            visibility,
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
            key_state,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_public_key_content_from_datakey() {
        let key1 = DataKey {
            id: 1,
            name: "Test Key".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public,
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: Some(2),
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![7, 8, 9, 10],
            public_key: vec![4, 5, 6],
            certificate: vec![1, 2, 3],
            create_at: Default::default(),
            expire_at: Default::default(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        let public_key_content = PublicKeyContent::try_from(key1).unwrap();
        assert_eq!(public_key_content.content, "\u{4}\u{5}\u{6}".to_string())
    }

    #[test]
    fn test_certificate_content_from_datakey() {
        let key1 = DataKey {
            id: 1,
            name: "Test Key".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public,
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: Some(2),
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![7, 8, 9, 10],
            public_key: vec![4, 5, 6],
            certificate: vec![1, 2, 3],
            create_at: Default::default(),
            expire_at: Default::default(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        let certificate_content = CertificateContent::try_from(key1).unwrap();
        assert_eq!(certificate_content.content, "\u{1}\u{2}\u{3}".to_string())
    }

    #[test]
    fn test_datakey_dto_from_datakey() {
        let key1 = DataKey {
            id: 1,
            name: "Test Key".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public,
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: Some(2),
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![7, 8, 9, 10],
            public_key: vec![4, 5, 6],
            certificate: vec![1, 2, 3],
            create_at: Default::default(),
            expire_at: Default::default(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        assert!(DataKeyDTO::try_from(key1).is_ok());
    }

    #[test]
    fn test_crl_content_from_crl_model() {
        let crl = X509CRL {
            id: 1,
            ca_id: 2,
            data: vec![1, 2, 3],
            create_at: Default::default(),
            update_at: Default::default(),
        };
        let crl_content = CRLContent::try_from(crl).unwrap();
        assert_eq!(crl_content.content, "\u{1}\u{2}\u{3}".to_string())
    }

    #[test]
    fn test_list_key_query() {
        let page_query_invalid1 = ListKeyQuery {
            key_type: Some("x509ee".to_string()),
            visibility: Some("public".to_string()),
            name: Some("test".to_string()),
            description: Some("test".to_string()),
            page_size: 9,
            page_number: 1,
        };
        assert!(page_query_invalid1.validate().is_err());
        let page_query_invalid2 = ListKeyQuery {
            key_type: Some("x509ee".to_string()),
            visibility: Some("public".to_string()),
            name: Some("test".to_string()),
            description: Some("test".to_string()),
            page_size: 101,
            page_number: 1,
        };
        assert!(page_query_invalid2.validate().is_err());
        let page_query_invalid3 = ListKeyQuery {
            key_type: Some("x509ee".to_string()),
            visibility: Some("public".to_string()),
            name: Some("test".to_string()),
            description: Some("test".to_string()),
            page_size: 100,
            page_number: 0,
        };
        assert!(page_query_invalid3.validate().is_err());
        let page_query_invalid4 = ListKeyQuery {
            key_type: Some("x509ee".to_string()),
            visibility: Some("public".to_string()),
            name: Some("test".to_string()),
            description: Some("test".to_string()),
            page_size: 100,
            page_number: 1001,
        };
        assert!(page_query_invalid4.validate().is_err());
        let query = ListKeyQuery {
            key_type: Some("x509ee".to_string()),
            visibility: Some("public".to_string()),
            name: Some("test".to_string()),
            description: Some("test".to_string()),
            page_size: 10,
            page_number: 1,
        };
        let datakey_query = DatakeyPaginationQuery::from(query);
        assert_eq!(datakey_query.key_type, Some("x509ee".to_string()));
        assert_eq!(datakey_query.visibility, Some("public".to_string()));
        assert_eq!(datakey_query.name, Some("test".to_string()));
        assert_eq!(datakey_query.description, Some("test".to_string()));
        assert_eq!(datakey_query.page_size, 10);
        assert_eq!(datakey_query.page_number, 1);
    }

    #[test]
    fn test_create_datakey_dto() {
        let invalid_name1 = CreateDataKeyDTO {
            name: "Tes".to_string(),
            description: "".to_string(),
            visibility: Some("public".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp".to_string(),
            parent_id: Some(2),
            expire_at: Default::default(),
        };
        assert!(invalid_name1.validate().is_err());
        let invalid_name2 = CreateDataKeyDTO {
            name: "1234567890123456789012345678901234567890123456789012345678901234\
            567890123456789012345678901234567890123456789012345678901234567890123456\
            7890123456789012345678901234567890123456789012345678901234567890123456789\
            012345678901234567890123456789012345678901234567890"
                .to_string(),
            description: "".to_string(),
            visibility: Some("public".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp".to_string(),
            parent_id: Some(2),
            expire_at: Default::default(),
        };
        assert!(invalid_name2.validate().is_err());
        let invalid_desc1 = CreateDataKeyDTO {
            name: "Test".to_string(),
            description: "1234567890123456789012345678901234567890123456789012345678901234\
            567890123456789012345678901234567890123456789012345678901234567890123456\
            7890123456789012345678901234567890123456789012345678901234567890123456789\
            012345678901234567890123456789012345678901234567890"
                .to_string(),
            visibility: Some("public".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp".to_string(),
            parent_id: Some(2),
            expire_at: Default::default(),
        };
        assert!(invalid_desc1.validate().is_err());
        let invalid_visibility = CreateDataKeyDTO {
            name: "Test".to_string(),
            description: "test descr".to_string(),
            visibility: Some("123".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp".to_string(),
            parent_id: Some(2),
            expire_at: Default::default(),
        };
        assert!(invalid_visibility.validate().is_err());

        let invalid_type = CreateDataKeyDTO {
            name: "Test".to_string(),
            description: "test descr".to_string(),
            visibility: Some("public".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp1".to_string(),
            parent_id: Some(2),
            expire_at: Default::default(),
        };
        assert!(invalid_type.validate().is_err());

        let invalid_expire = CreateDataKeyDTO {
            name: "Test".to_string(),
            description: "test descr".to_string(),
            visibility: Some("public".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp".to_string(),
            parent_id: Some(2),
            expire_at: "fake time".to_string(),
        };
        assert!(invalid_expire.validate().is_err());

        let dto = CreateDataKeyDTO {
            name: "Test".to_string(),
            description: "test descr".to_string(),
            visibility: Some("public".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp".to_string(),
            parent_id: Some(2),
            expire_at: Utc::now().to_string(),
        };
        let identity = UserIdentity {
            email: "email1".to_string(),
            id: 1,
            csrf_generation_token: None,
            csrf_token: None,
        };
        let key = DataKey::create_from(dto, identity.clone()).unwrap();
        assert_eq!(key.user, identity.id);
        assert_eq!(key.key_state, KeyState::Disabled);
        assert_eq!(key.key_type, KeyType::OpenPGP);
        assert_eq!(key.attributes.keys().len(), 3);
    }

    #[test]
    fn test_import_datakey_dto() {
        let invalid_name1 = ImportDataKeyDTO {
            name: "Tes".to_string(),
            description: "".to_string(),
            visibility: Some("public".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp".to_string(),
            certificate: "1234".to_string(),
            public_key: "1234".to_string(),
            private_key: "1234".to_string(),
        };
        assert!(invalid_name1.validate().is_err());
        let invalid_name2 = ImportDataKeyDTO {
            name: "1234567890123456789012345678901234567890123456789012345678901234\
            567890123456789012345678901234567890123456789012345678901234567890123456\
            7890123456789012345678901234567890123456789012345678901234567890123456789\
            012345678901234567890123456789012345678901234567890"
                .to_string(),
            description: "".to_string(),
            visibility: Some("public".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp".to_string(),
            certificate: "1234".to_string(),
            public_key: "1234".to_string(),
            private_key: "1234".to_string(),
        };
        assert!(invalid_name2.validate().is_err());
        let invalid_desc1 = ImportDataKeyDTO {
            name: "Test".to_string(),
            description: "1234567890123456789012345678901234567890123456789012345678901234\
            567890123456789012345678901234567890123456789012345678901234567890123456\
            7890123456789012345678901234567890123456789012345678901234567890123456789\
            012345678901234567890123456789012345678901234567890"
                .to_string(),
            visibility: Some("public".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp".to_string(),
            certificate: "1234".to_string(),
            public_key: "1234".to_string(),
            private_key: "1234".to_string(),
        };
        assert!(invalid_desc1.validate().is_err());
        let invalid_visibility = ImportDataKeyDTO {
            name: "Test".to_string(),
            description: "test descr".to_string(),
            visibility: Some("123".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp".to_string(),
            certificate: "1234".to_string(),
            public_key: "1234".to_string(),
            private_key: "1234".to_string(),
        };
        assert!(invalid_visibility.validate().is_err());

        let invalid_type = ImportDataKeyDTO {
            name: "Test".to_string(),
            description: "test descr".to_string(),
            visibility: Some("public".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp1".to_string(),
            certificate: "1234".to_string(),
            public_key: "1234".to_string(),
            private_key: "1234".to_string(),
        };
        assert!(invalid_type.validate().is_err());

        let dto = ImportDataKeyDTO {
            name: "Test".to_string(),
            description: "test descr".to_string(),
            visibility: Some("public".to_string()),
            attributes: HashMap::new(),
            key_type: "pgp".to_string(),
            certificate: "1234".to_string(),
            public_key: "1234".to_string(),
            private_key: "1234".to_string(),
        };
        let identity = UserIdentity {
            email: "email1".to_string(),
            id: 1,
            csrf_generation_token: None,
            csrf_token: None,
        };
        let key = DataKey::import_from(dto, identity.clone()).unwrap();
        assert_eq!(key.user, identity.id);
        assert_eq!(key.key_state, KeyState::Disabled);
        assert_eq!(key.key_type, KeyType::OpenPGP);
        assert_eq!(key.attributes.keys().len(), 2);
    }
}
