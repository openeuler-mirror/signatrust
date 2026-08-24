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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(lb_type: &str, server: &str, port: &str) -> HashMap<String, Value> {
        let mut config = HashMap::new();
        config.insert("type".to_string(), Value::from(lb_type));
        config.insert("server_address".to_string(), Value::from(server));
        config.insert("server_port".to_string(), Value::from(port));
        config
    }

    #[tokio::test]
    async fn test_channel_factory_single_lb() {
        let config = make_config("single", "127.0.0.1", "8088");
        let factory = ChannelFactory::new(&config).await.unwrap();
        let channel = factory.get_channel();
        assert!(channel.is_ok());
    }

    #[tokio::test]
    async fn test_channel_factory_dns_lb_construction() {
        let config = make_config("dns", "signatrust.example.com", "8088");
        // Factory construction succeeds; channel resolution depends on DNS
        let factory = ChannelFactory::new(&config).await.unwrap();
        let _channel = factory.get_channel();
        // Channel result depends on DNS — just verify no panic
    }

    #[tokio::test]
    async fn test_channel_factory_invalid_type() {
        let config = make_config("invalid_lb_type", "127.0.0.1", "8088");
        let result = ChannelFactory::new(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_channel_factory_missing_server_address() {
        let mut config = HashMap::new();
        config.insert("type".to_string(), Value::from("single"));
        // server_address and server_port missing
        let result = ChannelFactory::new(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_channel_factory_missing_port() {
        let mut config = HashMap::new();
        config.insert("type".to_string(), Value::from("single"));
        config.insert("server_address".to_string(), Value::from("127.0.0.1"));
        let result = ChannelFactory::new(&config).await;
        assert!(result.is_err());
    }
}
