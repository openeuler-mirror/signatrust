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
use crate::util::error::{Error, Result};
use async_trait::async_trait;
use config::Value;
use reqwest::{header::HeaderValue, Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::Mutex;
use secstr::*;

static SIGN_HEADER: &str = "x-auth-token";
static AUTH_HEADER: &str = "x-subject-token";

#[derive(Debug, Serialize, Deserialize)]
struct EncodeData {
    key_id: String,
    cipher_text: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecodeData {
    key_id: String,
    plain_text_base64: String,
    plain_text: String,
}

pub struct HuaweiCloudKMS {
    kms_id: String,
    username: String,
    password: SecUtf8,
    domain: String,
    project_name: String,
    project_id: String,
    endpoint: String,
    auth_token_cache: Mutex<String>,
    client: Client,
}

impl HuaweiCloudKMS {
    pub fn new(config: &HashMap<String, Value>) -> Result<HuaweiCloudKMS> {
        Ok(HuaweiCloudKMS {
            kms_id: config
                .get("kms_id")
                .unwrap_or(&Value::default())
                .to_string(),
            username: config
                .get("username")
                .unwrap_or(&Value::default())
                .to_string(),
            password: SecUtf8::from(config
                .get("password")
                .unwrap_or(&Value::default())
                .to_string()),
            domain: config
                .get("domain")
                .unwrap_or(&Value::default())
                .to_string(),
            project_name: config
                .get("project_name")
                .unwrap_or(&Value::default())
                .to_string(),
            project_id: config
                .get("project_id")
                .unwrap_or(&Value::default())
                .to_string(),
            endpoint: config
                .get("endpoint")
                .unwrap_or(&Value::default())
                .to_string(),
            auth_token_cache: Mutex::new("".to_string()),
            client: Client::new(),
        })
    }

    async fn auth_request(&self) -> Result<()> {
        if !self.auth_token_cache.lock().await.is_empty() {
            return Ok(());
        }
        let auth_content = json!({
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.username,
                            "password": self.password.unsecure(),
                            "domain": {
                                "name": self.domain
                            }
                        }
                    }
                },
                "scope": {
                    "domain": {
                        "name": self.domain,
                    },
                    "project": {
                        "name": self.project_name,
                    }
                }
            }
        });
        let res = self
            .client
            .post(format!("https://iam.{}/v3/auth/tokens", self.endpoint))
            .json(&auth_content)
            .send()
            .await?;
        if res.status() != StatusCode::CREATED {
            return Err(Error::KMSInvokeError(format!(
                "failed to get huaweicloud token {} {:?}",
                res.status(),
                res.headers()
            )));
        }
        self.auth_token_cache
            .lock()
            .await
            .push_str(res.headers()[AUTH_HEADER].to_str()?);
        Ok(())
    }

    async fn do_request<T: Serialize + ?Sized>(
        &self,
        url: &str,
        json: &T,
    ) -> Result<serde_json::Value> {
        self.auth_request().await?;
        let mut res = self
            .client
            .post(url)
            .header(
                SIGN_HEADER,
                HeaderValue::from_str(self.auth_token_cache.lock().await.as_str())?,
            )
            .json(json)
            .send()
            .await?;
        if res.status() == StatusCode::UNAUTHORIZED {
            //re authentication again
            self.auth_token_cache.lock().await.clear();
            self.auth_request().await?;
            res = self
                .client
                .post(url)
                .header(
                    SIGN_HEADER,
                    HeaderValue::from_str(self.auth_token_cache.lock().await.as_str())?,
                )
                .json(json)
                .send()
                .await?;
        }
        if res.status() != StatusCode::OK {
            return Err(Error::KMSInvokeError(format!(
                "unable to encode/decode data in kms, result {}",
                res.status()
            )));
        }
        Ok(res.json::<serde_json::Value>().await?)
    }
}

#[async_trait]
impl KMSProvider for HuaweiCloudKMS {
    async fn encode(&self, content: String) -> Result<String> {
        let request = json!({
            "key_id": self.kms_id,
            "plain_text": content,
            "encryption_algorithm": "SYMMETRIC_DEFAULT"
        });
        let result = self
            .do_request(
                format!(
                    "https://kms.{}/v1.0/{}/kms/encrypt-data",
                    self.endpoint, self.project_id
                )
                .as_str(),
                &request,
            )
            .await?;
        let encoded: EncodeData = serde_json::from_value(result)?;
        Ok(encoded.cipher_text)
    }

    async fn decode(&self, content: String) -> Result<String> {
        let request = json!({
            "key_id": self.kms_id,
            "cipher_text": content,
            "encryption_algorithm": "SYMMETRIC_DEFAULT"
        });
        let result = self
            .do_request(
                format!(
                    "https://kms.{}/v1.0/{}/kms/decrypt-data",
                    self.endpoint, self.project_id
                )
                .as_str(),
                &request,
            )
            .await?;
        let decode: DecodeData = serde_json::from_value(result)?;
        Ok(decode.plain_text)
    }
}
