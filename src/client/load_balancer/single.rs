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

use super::traits::DynamicLoadBalancer;
use tonic::transport::{Channel, ClientTlsConfig};

use crate::util::error::Result;
use async_trait::async_trait;
use tonic::transport::Endpoint;

pub struct SingleLoadBalancer {
    server: String,
    port: String,
    client_config: Option<ClientTlsConfig>,
}

impl SingleLoadBalancer {
    pub fn new(
        server: String,
        port: String,
        client_config: Option<ClientTlsConfig>,
    ) -> Result<Self> {
        Ok(Self {
            server,
            port,
            client_config,
        })
    }
}

#[async_trait]
impl DynamicLoadBalancer for SingleLoadBalancer {
    fn get_transport_channel(&self) -> Result<Channel> {
        let mut endpoint = Endpoint::from_shared(format!("http://{}:{}", self.server, self.port))?;
        if let Some(tls_config) = self.client_config.clone() {
            endpoint = endpoint.tls_config(tls_config)?
        }
        Ok(Channel::balance_list(vec![endpoint].into_iter()))
    }
}
