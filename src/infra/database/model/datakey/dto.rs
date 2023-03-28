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

use crate::domain::datakey::entity::{DataKey, KeyState};
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
    pub user: i32,
    pub email: String,
    pub attributes: String,
    pub key_type: String,
    pub private_key: String,
    pub public_key: String,
    pub certificate: String,
    pub create_at: DateTime<Utc>,
    pub expire_at: DateTime<Utc>,
    pub soft_delete: bool,
    pub key_state: String
}


impl TryFrom<DataKeyDTO> for DataKey {
    type Error = Error;

    fn try_from(dto: DataKeyDTO) -> std::result::Result<Self, Self::Error> {
        Ok(DataKey {
            id: dto.id,
            name: dto.name.clone(),
            description: dto.description.clone(),
            user: dto.user,
            email: dto.email.clone(),
            attributes: serde_json::from_str(dto.attributes.as_str())?,
            key_type: KeyType::from_str(&dto.key_type)?,
            private_key: key::decode_hex_string_to_u8(&dto.private_key),
            public_key: key::decode_hex_string_to_u8(&dto.public_key),
            certificate: key::decode_hex_string_to_u8(&dto.certificate),
            create_at: dto.create_at,
            expire_at: dto.expire_at,
            soft_delete: dto.soft_delete,
            key_state: KeyState::from_str(&dto.key_state)?,
        })
    }
}

impl TryFrom<DataKey> for DataKeyDTO {
    type Error = Error;

    fn try_from(data_key: DataKey) -> std::result::Result<Self, Self::Error> {
        Ok(DataKeyDTO {
            id: data_key.id,
            name: data_key.name.clone(),
            description: data_key.description.clone(),
            user: data_key.user,
            email: data_key.email.clone(),
            attributes: data_key.serialize_attributes()?,
            key_type: data_key.key_type.to_string(),
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
            soft_delete: data_key.soft_delete,
            key_state: data_key.key_state.to_string(),
        })
    }
}
