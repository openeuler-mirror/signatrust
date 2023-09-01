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
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use sqlx::FromRow;
use chrono::{DateTime, Utc};
use crate::domain::datakey::entity::{RevokedKey, X509CRL, X509RevokeReason};
use crate::util::error::Error;

use sqlx::types::chrono;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use crate::util::key::encode_u8_to_hex_string;


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

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

