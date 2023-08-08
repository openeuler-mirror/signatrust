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

use std::collections::HashMap;
use crate::util::error::{Result, Error};

pub mod signatrust {
    tonic::include_proto!("signatrust");
}

use tonic::transport::Channel;
use self::signatrust::{
    signatrust_client::SignatrustClient, GetKeyInfoRequest
};

pub struct KeyFetcher {
    client: SignatrustClient<Channel>,
    token: Option<String>,
}

impl KeyFetcher {

    pub fn new(channel: Channel, token: Option<String>) -> Self {
        Self {
            client: SignatrustClient::new(channel),
            token
        }
    }

    pub async fn get_key_attributes(&mut self, key_name: &str, key_type: &str) -> Result<HashMap<String, String>> {
        let key = GetKeyInfoRequest{
            key_type: key_type.to_string(),
            key_id: key_name.to_string(),
            token: self.token.clone(),
        };
        match self.client.get_key_info(key).await {
            Ok(result) => {
                let data = result.into_inner();
                if data.error.is_empty() {
                    Ok(data.attributes)
                } else {
                    Err(Error::RemoteSignError(format!("{:?}", data.error)))
                }
            }
            Err(err) => {
                Err(Error::RemoteSignError(format!("{:?}", err)))
            }
        }
    }
}
