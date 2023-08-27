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

use std::str::FromStr;
use crate::domain::sign_service::{SignBackend, SignBackendType};
use crate::util::error::{Result};
use std::sync::{Arc, RwLock};
use config::{Config};
use sea_orm::DatabaseConnection;
use crate::infra::sign_backend::memory::backend::MemorySignBackend;

pub struct SignBackendFactory {}

impl SignBackendFactory {
    pub async fn new_engine(config: Arc<RwLock<Config>>, db_connection: DatabaseConnection) -> Result<Box<dyn SignBackend>> {
        let engine_type = SignBackendType::from_str(
            config.read()?.get_string("sign-backend.type")?.as_str(),
        )?;
        info!("sign backend configured with plugin {:?}", engine_type);
        match engine_type {
            SignBackendType::Memory => Ok(Box::new(MemorySignBackend::new(config, db_connection).await?)),
        }
    }
}
