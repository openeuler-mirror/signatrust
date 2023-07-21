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

use crate::domain::datakey::entity::{DataKey, KeyState, Visibility, X509CRL};
use crate::domain::datakey::entity::KeyType;
use crate::domain::datakey::traits::ExtendableAttributes;
use crate::util::error::{Error};
use crate::util::key;

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use std::str::FromStr;

#[derive(Debug, FromRow)]
pub(super) struct DataKeyDTO {
    pub id: i32,
    pub name: String,
    pub description: String,
    pub visibility: String,
    pub user: i32,
    pub attributes: String,
    pub key_type: String,
    pub parent_id: Option<i32>,
    pub fingerprint: String,
    pub serial_number: Option<String>,
    pub private_key: String,
    pub public_key: String,
    pub certificate: String,
    pub create_at: DateTime<Utc>,
    pub expire_at: DateTime<Utc>,
    pub key_state: String,
    #[sqlx(default)]
    pub user_email: Option<String>,
    #[sqlx(default)]
    pub request_delete_users: Option<String>,
    #[sqlx(default)]
    pub request_revoke_users: Option<String>,
    #[sqlx(default)]
    pub x509_crl_update_at: Option<DateTime<Utc>>
}


impl TryFrom<DataKeyDTO> for DataKey {
    type Error = Error;

    fn try_from(dto: DataKeyDTO) -> Result<Self, Self::Error> {
        Ok(DataKey {
            id: dto.id,
            name: dto.name.clone(),
            visibility: Visibility::from_str(dto.visibility.as_str())?,
            description: dto.description.clone(),
            user: dto.user,
            attributes: serde_json::from_str(dto.attributes.as_str())?,
            key_type: KeyType::from_str(&dto.key_type)?,
            parent_id: dto.parent_id,
            fingerprint: dto.fingerprint.clone(),
            serial_number: dto.serial_number,
            private_key: key::decode_hex_string_to_u8(&dto.private_key),
            public_key: key::decode_hex_string_to_u8(&dto.public_key),
            certificate: key::decode_hex_string_to_u8(&dto.certificate),
            create_at: dto.create_at,
            expire_at: dto.expire_at,
            key_state: KeyState::from_str(&dto.key_state)?,
            user_email: dto.user_email,
            request_delete_users: dto.request_delete_users,
            request_revoke_users: dto.request_revoke_users,
            parent_key: None,
        })
    }
}

impl TryFrom<DataKey> for DataKeyDTO {
    type Error = Error;

    fn try_from(data_key: DataKey) -> Result<Self, Self::Error> {
        Ok(DataKeyDTO {
            id: data_key.id,
            name: data_key.name.clone(),
            description: data_key.description.clone(),
            visibility: data_key.visibility.to_string(),
            user: data_key.user,
            attributes: data_key.serialize_attributes()?,
            key_type: data_key.key_type.to_string(),
            parent_id: data_key.parent_id,
            fingerprint: data_key.fingerprint.clone(),
            serial_number: data_key.serial_number,
            private_key: key::encode_u8_to_hex_string(
                &data_key.private_key
            ),
            public_key: key::encode_u8_to_hex_string(
                &data_key.public_key
            ),
            certificate: key::encode_u8_to_hex_string(
                &data_key.certificate
            ),
            create_at: data_key.create_at,
            expire_at: data_key.expire_at,
            key_state: data_key.key_state.to_string(),
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            x509_crl_update_at: None,
        })
    }
}

#[derive(Debug, FromRow)]
pub struct X509CRLDTO {
    pub id: i32,
    pub ca_id: i32,
    pub data: String,
    pub create_at: DateTime<Utc>,
    pub update_at: DateTime<Utc>,
}

impl TryFrom<X509CRLDTO> for X509CRL {
    type Error = Error;

    fn try_from(value: X509CRLDTO) -> Result<Self, Self::Error> {
        Ok(X509CRL {
            id: value.id,
            ca_id: value.ca_id,
            data: key::decode_hex_string_to_u8(&value.data),
            create_at: value.create_at,
            update_at: value.update_at,
        })
    }
}

impl TryFrom<X509CRL> for X509CRLDTO {
    type Error = Error;

    fn try_from(value: X509CRL) -> Result<Self, Self::Error> {
        Ok(X509CRLDTO {
            id: value.id,
            ca_id: value.ca_id,
            data: key::encode_u8_to_hex_string(&value.data),
            create_at: value.create_at,
            update_at: value.update_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use super::*;
    use crate::domain::datakey::entity::{Visibility};

    #[test]
    fn test_data_key_dto_from_entity() {
        let key = DataKey{
            id: 0,
            name: "Test Key".to_string(),
            visibility: Visibility::Public,
            description: "test key description".to_string(),
            user: 0,
            attributes: HashMap::new(),
            key_type: KeyType::OpenPGP,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![1,2,3],
            public_key: vec![4,5,6],
            certificate: vec![7,8,9,10],
            create_at: Utc::now(),
            expire_at: Utc::now(),
            key_state: KeyState::Disabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        let dto = DataKeyDTO::try_from(key).unwrap();
        assert_eq!(dto.id, 0);
        assert_eq!(dto.name, "Test Key");
        assert_eq!(dto.visibility, Visibility::Public.to_string());
        assert_eq!(dto.key_state, KeyState::Disabled.to_string());
        assert_eq!(dto.private_key, "010203");
        assert_eq!(dto.public_key, "040506");
        assert_eq!(dto.certificate, "0708090A");
    }

    #[test]
    fn test_data_key_entity_from_dto() {
        let dto = DataKeyDTO {
            id: 1,
            name: "Test Key".to_string(),
            description: "".to_string(),
            visibility: Visibility::Public.to_string(),
            user: 0,
            attributes: "{}".to_string(),
            key_type: "pgp".to_string(),
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: "0708090A".to_string(),
            public_key: "040506".to_string(),
            certificate: "010203".to_string(),
            create_at: Utc::now(),
            expire_at: Utc::now(),
            key_state: "disabled".to_string(),
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            x509_crl_update_at: None,
        };
        let key = DataKey::try_from(dto).unwrap();
        assert_eq!(key.id, 1);
        assert_eq!(key.name, "Test Key");
        assert_eq!(key.visibility, Visibility::Public);
        assert_eq!(key.key_type, KeyType::OpenPGP);
        assert_eq!(key.private_key, vec![7,8,9,10]);
        assert_eq!(key.public_key, vec![4,5,6]);
        assert_eq!(key.certificate, vec![1,2,3]);
    }

}

