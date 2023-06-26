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

use crate::domain::encryption_engine::EncryptionEngine;
use crate::util::error::Result;
use async_trait::async_trait;


#[derive(Default)]
pub struct DummyEngine {}

#[async_trait]
impl EncryptionEngine for DummyEngine {
    async fn initialize(&mut self) -> Result<()> {
        warn!("dummy engine used for encryption, please don't use it in production environment");
        Ok(())
    }

    async fn rotate_key(&mut self) -> Result<bool> {
        warn!("dummy engine used for encryption, please don't use it in production environment");
        Ok(true)
    }

    async fn encode(&self, content: Vec<u8>) -> Result<Vec<u8>> {
        warn!("dummy engine used for encryption, please don't use it in production environment");
        Ok(content)
    }

    async fn decode(&self, content: Vec<u8>) -> Result<Vec<u8>> {
        warn!("dummy engine used for encryption, please don't use it in production environment");
        Ok(content)
    }
}