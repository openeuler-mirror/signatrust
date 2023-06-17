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
use crate::util::error::Error;

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


#[derive(Debug, FromRow)]
pub struct PendingOperationDTO {
    pub id: i32,
    pub user_id: i32,
    pub key_id: i32,
    pub request_type: RequestType,
    pub reason: Option<String>,
    pub user_email: String,
    pub create_at: DateTime<Utc>,
}

impl PendingOperationDTO {
    pub fn new_for_delete(key_id: i32, user_id: i32, user_email: String, reason: Option<String>) -> Self {
        Self {
            id: 0,
            user_id,
            key_id,
            user_email,
            create_at: Utc::now(),
            request_type: RequestType::Delete,
            reason
        }
    }

    pub fn new_for_revoke(key_id: i32, user_id: i32, user_email: String, reason: String) -> Self {
        Self {
            id: 0,
            user_id,
            key_id,
            user_email,
            create_at: Utc::now(),
            request_type: RequestType::Revoke,
            reason: Some(reason)
        }
    }
}