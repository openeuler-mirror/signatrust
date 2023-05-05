/*
 * // Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 * //
 * // signatrust is licensed under Mulan PSL v2.
 * // You can use this software according to the terms and conditions of the Mulan
 * // PSL v2.
 * // You may obtain a copy of Mulan PSL v2 at:
 * //         http://license.coscl.org.cn/MulanPSL2
 * // THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * // KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * // NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * // See the Mulan PSL v2 for more details.
 */
use validator::{ValidationError};
use chrono::{DateTime, Utc};

pub fn validate_utc_time_not_expire(expire: &str) -> Result<(), ValidationError> {
    let now = Utc::now();
    match expire.parse::<DateTime<Utc>>() {
        Ok(expire) => {
            if expire <= now {
                return Err(ValidationError::new("expire time less than current time"))
            }
            Ok(())
        },
        Err(_e) => {
            Err(ValidationError::new("failed to parse time string to utc"))
        }
    }
}

pub fn validate_utc_time(expire: &str) -> Result<(), ValidationError> {
    match expire.parse::<DateTime<Utc>>() {
        Ok(_) => {
            Ok(())
        },
        Err(_) => {
            Err(ValidationError::new("failed to parse time string to utc"))
        }
    }
}