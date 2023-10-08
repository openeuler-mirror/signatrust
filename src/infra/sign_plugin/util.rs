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
use crate::util::error::{Error, Result as CommonResult};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::HashMap;
use validator::{Validate, ValidationError};

pub fn validate_utc_time_not_expire(expire: &str) -> Result<(), ValidationError> {
    let now = Utc::now();
    match expire.parse::<DateTime<Utc>>() {
        Ok(expire) => {
            if expire <= now {
                return Err(ValidationError::new("expire time less than current time"));
            }
            Ok(())
        }
        Err(_e) => Err(ValidationError::new("failed to parse time string to utc")),
    }
}

pub fn validate_utc_time(expire: &str) -> Result<(), ValidationError> {
    match expire.parse::<DateTime<Utc>>() {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationError::new("failed to parse time string to utc")),
    }
}

pub fn attributes_validate<T: Validate + for<'a> Deserialize<'a>>(
    attr: &HashMap<String, String>,
) -> CommonResult<T> {
    let parameter: T = serde_json::from_str(serde_json::to_string(attr)?.as_str())?;
    match parameter.validate() {
        Ok(_) => Ok(parameter),
        Err(e) => Err(Error::ParameterError(format!("{:?}", e))),
    }
}
