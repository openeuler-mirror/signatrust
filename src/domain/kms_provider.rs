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

use crate::util::error::{Error, Result};
use async_trait::async_trait;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub enum KMSType {
    HuaweiCloud,
    Dummy,
}

impl FromStr for KMSType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "huaweicloud" => Ok(KMSType::HuaweiCloud),
            "dummy" => Ok(KMSType::Dummy),
            _ => Err(Error::UnsupportedTypeError(format!("{} kms type", s))),
        }
    }
}

#[async_trait]
pub trait KMSProvider: Send + Sync {
    async fn encode(&self, content: String) -> Result<String>;
    async fn decode(&self, content: String) -> Result<String>;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_kms_type_from_string_and_display() {
        let _ = KMSType::from_str("invalid_type")
            .expect_err("kms type from invalid string should fail");
        let kms_type1 = KMSType::from_str("huaweicloud").expect("kms type from string failed");
        assert_eq!(kms_type1, KMSType::HuaweiCloud);
        let kms_type2 = KMSType::from_str("dummy").expect("kms type from string failed");
        assert_eq!(kms_type2, KMSType::Dummy);
    }
}
