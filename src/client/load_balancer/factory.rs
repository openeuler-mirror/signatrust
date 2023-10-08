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

use crate::client::load_balancer::dns::DNSLoadBalancer;
use crate::client::load_balancer::single::SingleLoadBalancer;
use crate::client::load_balancer::traits::DynamicLoadBalancer;
use crate::util::error::Error::ConfigError;
use crate::util::error::{Error, Result};
use crate::util::key::file_exists;
use config::Value;
use std::collections::HashMap;
use tonic::transport::{Channel, ClientTlsConfig, Identity};

pub struct ChannelFactory {
    lb: Box<dyn DynamicLoadBalancer>,
}

impl ChannelFactory {
    pub async fn new(config: &HashMap<String, Value>) -> Result<Self> {
        let mut client_config: Option<ClientTlsConfig> = None;
        let tls_cert = config
            .get("tls_cert")
            .unwrap_or(&Value::new(
                Some(&String::new()),
                config::ValueKind::String(String::new()),
            ))
            .to_string();
        let tls_key = config
            .get("tls_key")
            .unwrap_or(&Value::new(
                Some(&String::new()),
                config::ValueKind::String(String::new()),
            ))
            .to_string();
        let server_address = config
            .get("server_address")
            .unwrap_or(&Value::new(
                Some(&String::new()),
                config::ValueKind::String(String::new()),
            ))
            .to_string();
        let server_port = config
            .get("server_port")
            .unwrap_or(&Value::new(
                Some(&String::new()),
                config::ValueKind::String(String::new()),
            ))
            .to_string();
        if server_address.is_empty() || server_port.is_empty() {
            return Err(ConfigError(format!(
                "server address: {} or port: {} not configured",
                server_address, server_port
            )));
        }
        if tls_cert.is_empty() || tls_key.is_empty() {
            info!("tls client key and cert not configured, tls will be disabled");
        } else {
            info!("tls client key and cert configured, tls will be enabled");
            debug!("tls cert:{}, tls key:{}", tls_cert, tls_key);
            if !file_exists(&tls_cert) || !file_exists(&tls_key) {
                return Err(Error::FileFoundError(format!(
                    "client tls cert {} or key {} file not found",
                    tls_key, tls_cert
                )));
            }
            let identity = Identity::from_pem(
                tokio::fs::read(tls_cert).await?,
                tokio::fs::read(tls_key).await?,
            );
            client_config = Some(
                ClientTlsConfig::new().identity(identity).domain_name(
                    config
                        .get("domain_name")
                        .unwrap_or(&Value::default())
                        .to_string(),
                ),
            );
        }
        let lb_type = config.get("type").unwrap_or(&Value::default()).to_string();
        if lb_type == "single" {
            return Ok(Self {
                lb: Box::new(SingleLoadBalancer::new(
                    server_address,
                    server_port,
                    client_config,
                )?),
            });
        } else if lb_type == "dns" {
            return Ok(Self {
                lb: Box::new(DNSLoadBalancer::new(
                    server_address,
                    server_port,
                    client_config,
                )?),
            });
        }
        Err(ConfigError(format!(
            "invalid load balancer type configuration: {}",
            lb_type
        )))
    }

    pub fn get_channel(&self) -> Result<Channel> {
        self.lb.get_transport_channel()
    }
}
