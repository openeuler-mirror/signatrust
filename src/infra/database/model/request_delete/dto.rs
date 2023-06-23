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
use crate::domain::datakey::entity::{RevokedKey, X509RevokeReason};
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
pub struct RevokedKeyDTO {
    pub id: i32,
    pub key_id: i32,
    pub ca_id: i32,
    pub reason: String,
    pub serial_number: Option<String>,
    pub create_at: DateTime<Utc>,
}

impl RevokedKeyDTO {
    pub fn new(key_id: i32, ca_id: i32, reason: X509RevokeReason) -> Self {
        Self {
            id: 0,
            key_id,
            ca_id,
            create_at: Utc::now(),
            reason: reason.to_string(),
            serial_number: None,
        }
    }
}

impl TryFrom<RevokedKeyDTO> for RevokedKey {
    type Error = Error;

    fn try_from(dto: RevokedKeyDTO) -> Result<Self, Self::Error> {
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



#[derive(Debug, FromRow)]
pub struct PendingOperationDTO {
    pub id: i32,
    pub user_id: i32,
    pub key_id: i32,
    pub request_type: RequestType,
    pub user_email: String,
    pub create_at: DateTime<Utc>,
}

impl PendingOperationDTO {
    pub fn new_for_delete(key_id: i32, user_id: i32, user_email: String) -> Self {
        Self {
            id: 0,
            user_id,
            key_id,
            user_email,
            create_at: Utc::now(),
            request_type: RequestType::Delete,
        }
    }

    pub fn new_for_revoke(key_id: i32, user_id: i32, user_email: String) -> Self {
        Self {
            id: 0,
            user_id,
            key_id,
            user_email,
            create_at: Utc::now(),
            request_type: RequestType::Revoke,
        }
    }
}