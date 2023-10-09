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

use crate::domain::kms_provider::{KMSProvider, KMSType};
use crate::infra::kms::dummy::DummyKMS;
use crate::infra::kms::huaweicloud::HuaweiCloudKMS;
use crate::util::error::Result;
use config::Value;
use std::collections::HashMap;
use std::str::FromStr;

pub struct KMSProviderFactory {}

impl KMSProviderFactory {
    pub fn new_provider(config: &HashMap<String, Value>) -> Result<Box<dyn KMSProvider>> {
        let kms_type = KMSType::from_str(
            config
                .get("type")
                .unwrap_or(&Value::default())
                .to_string()
                .as_str(),
        )?;
        info!("kms provider configured with {:?}", kms_type);
        match kms_type {
            KMSType::HuaweiCloud => Ok(Box::new(HuaweiCloudKMS::new(config)?)),
            KMSType::Dummy => Ok(Box::new(DummyKMS::new(config)?)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_kms_provider_factory() {
        let mut config = HashMap::new();
        config.insert("type".to_string(), Value::from("not_existed"));
        assert!(KMSProviderFactory::new_provider(&config).is_err());
        config.insert("type".to_string(), Value::from("dummy"));
        KMSProviderFactory::new_provider(&config)
            .expect("kms provider from valid string should succeed");
    }
}
