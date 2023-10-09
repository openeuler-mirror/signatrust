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
use secstr::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::Mutex;

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
    iam_endpoint: String,
    kms_endpoint: String,
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
            password: SecUtf8::from(
                config
                    .get("password")
                    .unwrap_or(&Value::default())
                    .to_string(),
            ),
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
            iam_endpoint: config
                .get("iam_endpoint")
                .unwrap_or(&Value::default())
                .to_string(),
            kms_endpoint: config
                .get("kms_endpoint")
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
            .post(format!("{}/v3/auth/tokens", self.iam_endpoint))
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
        //huaweicloud response with 403 when token expired.
        if res.status() == StatusCode::FORBIDDEN {
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
                    "{}/v1.0/{}/kms/encrypt-data",
                    self.kms_endpoint, self.project_id
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
                    "{}/v1.0/{}/kms/decrypt-data",
                    self.kms_endpoint, self.project_id
                )
                .as_str(),
                &request,
            )
            .await?;
        let decode: DecodeData = serde_json::from_value(result)?;
        Ok(decode.plain_text)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mockito;

    fn get_kms_config(
        iam_endpoint: Option<String>,
        kms_endpoint: Option<String>,
    ) -> HashMap<String, Value> {
        let mut config: HashMap<String, Value> = HashMap::new();
        config.insert("kms_id".to_string(), Value::from("fake_kms_id"));
        config.insert("username".to_string(), Value::from("fake_username"));
        config.insert("password".to_string(), Value::from("fake_password"));
        config.insert("domain".to_string(), Value::from("fake_domain"));
        config.insert("project_name".to_string(), Value::from("fake_project_name"));
        config.insert("project_id".to_string(), Value::from("fake_project_id"));
        match iam_endpoint {
            None => {
                config.insert("iam_endpoint".to_string(), Value::from("fake_endpoint"));
            }
            Some(value) => {
                config.insert("iam_endpoint".to_string(), Value::from(value));
            }
        }
        match kms_endpoint {
            None => {
                config.insert("kms_endpoint".to_string(), Value::from("fake_endpoint"));
            }
            Some(value) => {
                config.insert("kms_endpoint".to_string(), Value::from(value));
            }
        }
        return config;
    }

    #[tokio::test]
    async fn test_huaweicloud_encode_successful() {
        // Request a new server from the pool
        let mut iam_server = mockito::Server::new();
        let iam_url = iam_server.url();
        let mut kms_server = mockito::Server::new();
        let kms_url = kms_server.url();
        let config = get_kms_config(Some(iam_url.clone()), Some(kms_url));

        // Mock auth request
        let mock_auth = iam_server
            .mock("POST", "/v3/auth/tokens")
            .with_status(201)
            .with_header(AUTH_HEADER, "fake_auth_header")
            .create();

        let mock_encode = kms_server
            .mock("POST", "/v1.0/fake_project_id/kms/encrypt-data")
            .with_status(200)
            .match_header(SIGN_HEADER, "fake_auth_header")
            .with_body(r#"{"key_id": "123", "cipher_text": "encoded"}"#)
            .create();

        //create kms client
        let kms_client =
            HuaweiCloudKMS::new(&config).expect("create huaweicloud client should be successful");
        let result = kms_client
            .encode("raw_content".to_string())
            .await
            .expect("request invoke should be successful");

        assert_eq!("encoded", result);
        mock_auth.assert();
        mock_encode.assert();
    }

    #[tokio::test]
    async fn test_huaweicloud_decode_successful() {
        // Request a new server from the pool
        let mut iam_server = mockito::Server::new();
        let iam_url = iam_server.url();
        let mut kms_server = mockito::Server::new();
        let kms_url = kms_server.url();
        let config = get_kms_config(Some(iam_url.clone()), Some(kms_url));

        // Mock auth request
        let mock_auth = iam_server
            .mock("POST", "/v3/auth/tokens")
            .with_status(201)
            .with_header(AUTH_HEADER, "fake_auth_header")
            .create();

        let mock_decode = kms_server
            .mock("POST", "/v1.0/fake_project_id/kms/decrypt-data")
            .with_status(200)
            .match_header(SIGN_HEADER, "fake_auth_header")
            .with_body(r#"{"key_id": "123", "plain_text": "decoded", "plain_text_base64": "123"}"#)
            .create();

        //create kms client
        let kms_client =
            HuaweiCloudKMS::new(&config).expect("create huaweicloud client should be successful");
        let result = kms_client
            .decode("raw_content".to_string())
            .await
            .expect("request invoke should be successful");

        assert_eq!("decoded", result);
        mock_auth.assert();
        mock_decode.assert();
    }

    #[tokio::test]
    async fn test_huaweicloud_request_with_cache_successful() {
        // Request a new server from the pool
        let mut server = mockito::Server::new();
        let url = server.url();
        let config = get_kms_config(Some(url.clone()), None);

        // Mock auth request
        let mock_auth = server
            .mock("POST", "/v3/auth/tokens")
            .with_status(201)
            .create();

        //mock request with content
        let fake_request = json!({
            "fake_attribute": "123",
        });
        let mock_request = server
            .mock("POST", "/kms/fake_endpoint")
            .with_status(200)
            .match_header(SIGN_HEADER, "fake_auth_header")
            .match_body(mockito::Matcher::Json(fake_request.clone()))
            .with_body(r#"{"key_id": "123", "plain_text_base64": "456", "plain_text": "1234"}"#)
            .create();

        //create kms client
        let kms_client =
            HuaweiCloudKMS::new(&config).expect("create huaweicloud client should be successful");
        kms_client
            .auth_token_cache
            .lock()
            .await
            .push_str("fake_auth_header");

        let request_url = format!("{}/kms/fake_endpoint", url);
        let result = kms_client
            .do_request(&request_url, &fake_request)
            .await
            .expect("request invoke should be successful");
        let decoded: DecodeData = serde_json::from_value(result).expect("deserialize should ok");

        assert_eq!("123", decoded.key_id);
        assert_eq!("456", decoded.plain_text_base64);
        assert_eq!("1234", decoded.plain_text);
        //auth should not invoked
        mock_auth.expect_at_most(0).assert();
        mock_request.assert();
    }

    #[tokio::test]
    async fn test_huaweicloud_request_without_cache_successful() {
        // Request a new server from the pool
        let mut server = mockito::Server::new();
        let url = server.url();
        let config = get_kms_config(Some(url.clone()), None);

        // Mock auth request
        let mock_auth = server
            .mock("POST", "/v3/auth/tokens")
            .with_status(201)
            .with_header(AUTH_HEADER, "fake_auth_header")
            .create();

        //mock request with content
        let fake_request = json!({
            "fake_attribute": "123",
        });
        let mock_request = server
            .mock("POST", "/kms/decrypt-data")
            .with_status(200)
            .match_header(SIGN_HEADER, "fake_auth_header")
            .match_body(mockito::Matcher::Json(fake_request.clone()))
            .with_body(r#"{"key_id": "123", "plain_text_base64": "456", "plain_text": "1234"}"#)
            .create();

        //create kms client
        let kms_client =
            HuaweiCloudKMS::new(&config).expect("create huaweicloud client should be successful");
        let request_url = format!("{}/kms/decrypt-data", url);
        let result = kms_client
            .do_request(&request_url, &fake_request)
            .await
            .expect("request invoke should be successful");
        let decoded: DecodeData = serde_json::from_value(result).expect("deserialize should ok");

        assert_eq!("123", decoded.key_id);
        assert_eq!("456", decoded.plain_text_base64);
        assert_eq!("1234", decoded.plain_text);
        //auth should not invoked
        mock_auth.expect_at_most(1).assert();
        mock_request.assert();
    }

    #[tokio::test]
    async fn test_huaweicloud_request_without_cache_forbidden() {
        // Request a new server from the pool
        let mut server = mockito::Server::new();
        let url = server.url();
        let config = get_kms_config(Some(url.clone()), None);

        // Mock auth request
        let mock_auth = server
            .mock("POST", "/v3/auth/tokens")
            .with_status(201)
            .with_header(AUTH_HEADER, "fake_auth_header")
            .create();

        //mock request with content
        let fake_request = json!({
            "fake_attribute": "123",
        });
        let mock_request = server
            .mock("POST", "/kms/fake_endpoint")
            .with_status(403)
            .match_header(SIGN_HEADER, "fake_auth_header")
            .match_body(mockito::Matcher::Json(fake_request.clone()))
            .with_body(r#"{"key_id": "123", "plain_text_base64": "456", "plain_text": "1234"}"#)
            .create();

        //create kms client
        let kms_client =
            HuaweiCloudKMS::new(&config).expect("create huaweicloud client should be successful");
        let request_url = format!("{}/kms/fake_endpoint", url);
        let _result = kms_client
            .do_request(&request_url, &fake_request)
            .await
            .expect_err("always failed to invoke request");

        //auth and request should be invoked twice.
        mock_auth.expect_at_least(2).assert();
        mock_request.expect_at_least(2).assert();
    }

    #[tokio::test]
    async fn test_huaweicloud_auth_endpoint_failed() {
        // Request a new server from the pool
        let mut server = mockito::Server::new();
        let url = server.url();
        let config = get_kms_config(Some(url), None);

        // Create a mock server
        let mock = server
            .mock("POST", "/v3/auth/tokens")
            .with_status(500)
            .create();

        //create kms client
        let kms_client =
            HuaweiCloudKMS::new(&config).expect("create huaweicloud client should be successful");

        //test auth request
        assert_eq!(true, kms_client.auth_token_cache.lock().await.is_empty());
        kms_client
            .auth_request()
            .await
            .expect_err("auth request failed with 500 status code");
        mock.assert();
    }

    #[tokio::test]
    async fn test_huaweicloud_auth_endpoint_cache() {
        // Request a new server from the pool
        let mut server = mockito::Server::new();
        let url = server.url();
        let config = get_kms_config(Some(url), None);
        let request_body = json!({
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": "fake_username",
                            "password": "fake_password",
                            "domain": {
                                "name": "fake_domain"
                            }
                        }
                    }
                },
                "scope": {
                    "domain": {
                        "name": "fake_domain",
                    },
                    "project": {
                        "name": "fake_project_name",
                    }
                }
            }
        });

        // Create a mock server
        let mock = server
            .mock("POST", "/v3/auth/tokens")
            .with_status(201)
            .with_header(AUTH_HEADER, "fake_auth_header")
            .match_body(mockito::Matcher::Json(request_body))
            .create();

        //create kms client
        let kms_client =
            HuaweiCloudKMS::new(&config).expect("create huaweicloud client should be successful");

        //test auth request
        assert_eq!(true, kms_client.auth_token_cache.lock().await.is_empty());
        kms_client
            .auth_request()
            .await
            .expect("auth request should be successful");
        assert_eq!(
            "fake_auth_header",
            kms_client.auth_token_cache.lock().await.as_str()
        );
        mock.assert();
    }
}
