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
use chrono::{DateTime, Utc};
use crate::domain::datakey::entity::{X509CRL};
use crate::util::error::Error;

use sqlx::types::chrono;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use crate::util::key::{decode_hex_string_to_u8, encode_u8_to_hex_string};


#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Deserialize, Serialize)]
#[sea_orm(table_name = "x509_crl_content")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub ca_id: i32,
    pub data: String,
    pub create_at: DateTime<Utc>,
    pub update_at: DateTime<Utc>,
}

impl TryFrom<X509CRL> for Model {
    type Error = Error;

    fn try_from(value: X509CRL) -> Result<Self, Self::Error> {
        Ok(Model {
            id: value.id,
            ca_id: value.ca_id,
            data: encode_u8_to_hex_string(&value.data),
            create_at: value.create_at,
            update_at: value.update_at,
        })
    }
}

impl TryFrom<Model> for X509CRL {
    type Error = Error;

    fn try_from(value: Model) -> Result<Self, Self::Error> {
        Ok(X509CRL {
            id: value.id,
            ca_id: value.ca_id,
            data: decode_hex_string_to_u8(&value.data),
            create_at: value.create_at,
            update_at: value.update_at,
        })
    }
}


#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
    belongs_to = "super::super::datakey::dto::Entity",
    from = "Column::CaId",
    to = "super::super::datakey::dto::Column::Id"
    )]
    Datakey,
}

impl Related<super::super::datakey::dto::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Datakey.def()
    }
}
impl ActiveModelBehavior for ActiveModel {}

