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
use std::str::FromStr;
use chrono::{DateTime, Utc};
use crate::domain::datakey::entity::{RevokedKey, X509RevokeReason};
use crate::util::error::Error;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};


#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Deserialize, Serialize)]
#[sea_orm(table_name = "x509_keys_revoked")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub key_id: i32,
    pub ca_id: i32,
    pub reason: String,
    pub serial_number: Option<String>,
    pub create_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
impl TryFrom<Model> for RevokedKey {
    type Error = Error;

    fn try_from(dto: Model) -> Result<Self, Self::Error> {
        Ok(RevokedKey {
            id: dto.id,
            key_id: dto.key_id,
            ca_id: dto.ca_id,
            reason: X509RevokeReason::from_str(&dto.reason)?,
            create_at: dto.create_at,
            serial_number: dto.serial_number,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    #[test]
    fn test_revoked_key_dto_conversion() {
        let now = Utc::now();
        let dto = Model{
            id: 0,
            key_id: 1,
            ca_id: 2,
            reason: X509RevokeReason::KeyCompromise.to_string(),
            serial_number: None,
            create_at: now,
        };
        let revoked_key = RevokedKey::try_from(dto).unwrap();
        assert_eq!(revoked_key.key_id, 1);
        assert_eq!(revoked_key.ca_id, 2);
        assert_eq!(revoked_key.reason, X509RevokeReason::KeyCompromise);
        assert_eq!(revoked_key.create_at, now);
    }
}
