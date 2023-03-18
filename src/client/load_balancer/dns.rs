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

use tonic::transport::{Channel, ClientTlsConfig};
use super::traits::DynamicLoadBalancer;

use crate::util::error::Result;
use tonic::transport::Endpoint;
use async_trait::async_trait;


use dns_lookup::{lookup_host};

pub struct DNSLoadBalancer {
    hostname: String,
    port: String,
    client_config: Option<ClientTlsConfig>
}

impl DNSLoadBalancer {

    pub fn new(hostname: String, port: String, client_config: Option<ClientTlsConfig>) -> Result<Self> {
        Ok(Self {
            hostname,
            port,
            client_config
        })
    }

}

#[async_trait]
impl DynamicLoadBalancer for DNSLoadBalancer {
    fn get_transport_channel(&self) -> Result<Channel> {
        let mut endpoints = Vec::new();
        for ip in lookup_host(&self.hostname)?.into_iter() {
            let mut endpoint = Endpoint::from_shared(
                format!("http://{}:{}", ip, self.port))?;
            if let Some(tls_config) = self.client_config.clone() {
                endpoint = endpoint.tls_config(tls_config)?;
            }
            info!("found endpoint {}:{} for signing task.", ip, self.port);
            endpoints.push(endpoint);
        }
        Ok(Channel::balance_list(endpoints.into_iter()))
    }
}