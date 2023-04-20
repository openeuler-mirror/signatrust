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

use crate::domain::sign_plugin::SignPlugins;
use crate::infra::sign_plugin::openpgp::OpenPGPPlugin;
use crate::infra::sign_plugin::x509::X509Plugin;
use crate::domain::datakey::entity::{DataKeyContent, KeyType};
use crate::util::error::Result;
use std::collections::HashMap;

use crate::domain::datakey::entity::SecDataKey;

pub struct Signers {}

impl Signers {

    //get responding sign plugin for data signing
    pub fn load_from_data_key(key_type: &KeyType, data_key: SecDataKey) -> Result<Box<dyn SignPlugins>> {
        match key_type {
            KeyType::OpenPGP => Ok(Box::new(OpenPGPPlugin::new(data_key)?)),
            KeyType::X509 => Ok(Box::new(X509Plugin::new(data_key)?)),
        }
    }

    //generating new key, including private & public keys and the certificate, empty if not required.
    pub fn generate_keys(
        key_type: &KeyType,
        value: &HashMap<String, String>,
    ) -> Result<DataKeyContent> {
        match key_type {
            KeyType::OpenPGP => OpenPGPPlugin::generate_keys(value),
            KeyType::X509 => X509Plugin::generate_keys(value),
        }
    }
}
