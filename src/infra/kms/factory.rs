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

use crate::infra::kms::huaweicloud::HuaweiCloudKMS;
use crate::infra::kms::dummy::DummyKMS;
use crate::infra::kms::kms_provider::KMSProvider;
use crate::util::error::{Error, Result};
use config::Value;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug)]
enum KMSType {
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

pub struct KMSProviderFactory {}

impl KMSProviderFactory {
    pub fn new_provider(config: &HashMap<String, Value>) -> Result<Arc<Box<dyn KMSProvider>>> {
        let kms_type = KMSType::from_str(
            config
                .get("type")
                .unwrap_or(&Value::default())
                .to_string()
                .as_str(),
        )?;
        info!("kms provider configured with {:?}", kms_type);
        match kms_type {
            KMSType::HuaweiCloud => Ok(Arc::new(Box::new(HuaweiCloudKMS::new(config)?))),
            KMSType::Dummy => Ok(Arc::new(Box::new(DummyKMS::new(config)?))),
        }
    }
}
