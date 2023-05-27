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

use crate::domain::datakey::entity::{DataKey, KeyState, Visibility};
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
    pub fingerprint: String,
    pub private_key: String,
    pub public_key: String,
    pub certificate: String,
    pub create_at: DateTime<Utc>,
    pub expire_at: DateTime<Utc>,
    pub key_state: String,
    pub user_email: Option<String>,
    pub request_delete_users: Option<String>,
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
            fingerprint: dto.fingerprint.clone(),
            private_key: key::decode_hex_string_to_u8(&dto.private_key),
            public_key: key::decode_hex_string_to_u8(&dto.public_key),
            certificate: key::decode_hex_string_to_u8(&dto.certificate),
            create_at: dto.create_at,
            expire_at: dto.expire_at,
            key_state: KeyState::from_str(&dto.key_state)?,
            user_email: dto.user_email,
            request_delete_users: dto.request_delete_users
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
            fingerprint: data_key.fingerprint.clone(),
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
            request_delete_users: None
        })
    }
}
