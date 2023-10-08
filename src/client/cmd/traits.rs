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

use crate::util::error::Result;
use config::Config;
use std::sync::{atomic::AtomicBool, Arc, RwLock};

pub trait SignCommand: Clone {
    type CommandValue;
    fn new(
        signal: Arc<AtomicBool>,
        config: Arc<RwLock<Config>>,
        command: Self::CommandValue,
    ) -> Result<Self>;
    fn validate(&self) -> Result<()>;
    fn handle(&self) -> Result<bool>;
}
