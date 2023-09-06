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
use chrono::{DateTime, Utc};
use crate::util::error::Error;

use sqlx::types::chrono;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, sqlx::Type)]
pub enum RequestType {
    #[sqlx(rename = "delete")]
    Delete,
    #[sqlx(rename = "revoke")]
    Revoke,
}

impl Display for RequestType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestType::Delete => write!(f, "delete"),
            RequestType::Revoke => write!(f, "revoke"),
        }
    }
}

impl FromStr for RequestType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "delete" => Ok(RequestType::Delete),
            "revoke" => Ok(RequestType::Revoke),
            _ => Err(Error::UnsupportedTypeError(s.to_string()))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Deserialize, Serialize)]
#[sea_orm(table_name = "pending_operation")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub user_id: i32,
    pub key_id: i32,
    pub request_type: String,
    pub user_email: String,
    pub create_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}


impl Model {
    pub fn new_for_delete(key_id: i32, user_id: i32, user_email: String) -> Self {
        Self {
            id: 0,
            user_id,
            key_id,
            user_email,
            create_at: Utc::now(),
            request_type: RequestType::Delete.to_string(),
        }
    }

    pub fn new_for_revoke(key_id: i32, user_id: i32, user_email: String) -> Self {
        Self {
            id: 0,
            user_id,
            key_id,
            user_email,
            create_at: Utc::now(),
            request_type: RequestType::Revoke.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_type_display() {
        let delete = RequestType::Delete;
        assert_eq!(format!("{}", delete), "delete");

        let revoke = RequestType::Revoke;
        assert_eq!(format!("{}", revoke), "revoke");
    }

    #[test]
    fn test_request_type_from_str() {
        let delete = RequestType::from_str("delete").unwrap();
        assert_eq!(delete, RequestType::Delete);

        let revoke = RequestType::from_str("revoke").unwrap();
        assert_eq!(revoke, RequestType::Revoke);
    }

    #[test]
    fn test_pending_operation_dto() {
        let delete_dto = Model::new_for_delete(1, 2, "test@email.com".into());
        assert_eq!(delete_dto.request_type, RequestType::Delete.to_string());
        let revoke_dto = Model::new_for_revoke(3, 4, "test2@email.com".into());
        assert_eq!(revoke_dto.request_type, RequestType::Revoke.to_string());
    }
}
