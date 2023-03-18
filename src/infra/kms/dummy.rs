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

use crate::domain::kms_provider::KMSProvider;
use crate::util::error::{Result};
use config::Value;
use std::collections::HashMap;
use async_trait::async_trait;

pub struct DummyKMS {
}

impl DummyKMS {
    pub fn new(_config: &HashMap<String, Value>) -> Result<DummyKMS> {
        Ok(DummyKMS {})
    }
}

#[async_trait]
impl KMSProvider for DummyKMS {
    async fn encode(&self, content: String) -> Result<String> {
        warn!("dummy kms used for encoding, please don't use it in production environment");
        Ok(content)
    }

    async fn decode(&self, content: String) -> Result<String> {
        warn!("dummy kms used for decoding, please don't use it in production environment");
        Ok(content)
    }
}
