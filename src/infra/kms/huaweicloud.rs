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
use std::time::Duration;
use tokio::sync::Mutex;

static SIGN_HEADER: &str = "x-auth-token";
static AUTH_HEADER: &str = "x-subject-token";

/// Connection timeout for KMS HTTP requests.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Total timeout for a single KMS HTTP request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT)
                .build()?,
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
        self.do_request_with_retry(url, json, MAX_ATTEMPTS).await
    }

    /// Perform a single KMS request without retry. Kept separate so the retry
    /// loop can distinguish transient errors from permanent ones.
    async fn do_request_once<T: Serialize + ?Sized>(
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

    /// Perform a KMS request with exponential backoff on transient errors.
    ///
    /// Retryable errors: network-level errors (`Error::HttpRequest`) and KMS
    /// server errors (HTTP 5xx). Business errors (4xx other than the handled
    /// 403) are returned immediately without retry.
    async fn do_request_with_retry<T: Serialize + ?Sized>(
        &self,
        url: &str,
        json: &T,
        max_attempts: u32,
    ) -> Result<serde_json::Value> {
        for attempt in 1..=max_attempts {
            if attempt > 1 {
                let backoff_ms = INITIAL_BACKOFF_MS * 2u64.pow(attempt - 2);
                warn!(
                    "KMS request attempt {}/{}, backoff {}ms",
                    attempt, max_attempts, backoff_ms
                );
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
            }
            match self.do_request_once(url, json).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if !is_retryable_kms_error(&e) || attempt == max_attempts {
                        return Err(e);
                    }
                    warn!("KMS request failed (retryable): {}", e);
                }
            }
        }
        unreachable!("retry loop always returns within max_attempts")
    }
}

/// Total attempts for KMS requests (including the initial call).
const MAX_ATTEMPTS: u32 = 4;
/// Initial backoff in milliseconds for KMS retries.
const INITIAL_BACKOFF_MS: u64 = 100;

/// Determine whether a KMS error is retryable.
///
/// - `Error::HttpRequest` covers network-level failures (connection refused,
///   DNS failure, TLS error, timeout) which are transient by nature.
/// - `Error::KMSInvokeError` embeds the HTTP status code in the message
///   ("... result <code> ..."); only 5xx server errors are retried, other
///   status codes (e.g. 4xx business errors) are permanent.
fn is_retryable_kms_error(err: &Error) -> bool {
    match err {
        Error::HttpRequest(_) => true,
        Error::KMSInvokeError(msg) => msg
            .split("result ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|code| code.parse::<u16>().ok())
            .map(|code| (500..=599).contains(&code))
            .unwrap_or(false),
        _ => false,
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
        config
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
        assert!(kms_client.auth_token_cache.lock().await.is_empty());
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
        assert!(kms_client.auth_token_cache.lock().await.is_empty());
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

    #[tokio::test]
    async fn test_kms_retry_on_5xx_exhausted() {
        let mut server = mockito::Server::new();
        let url = server.url();
        let config = get_kms_config(Some(url.clone()), Some(url.clone()));

        // Mock auth (called once; token cached across retries)
        let mock_auth = server
            .mock("POST", "/v3/auth/tokens")
            .with_status(201)
            .with_header(AUTH_HEADER, "fake_auth_header")
            .expect(1)
            .create();

        // Always 503 → all MAX_ATTEMPTS attempts fail
        let mock_request = server
            .mock("POST", "/kms/fake_endpoint")
            .with_status(503)
            .with_body(r#"{"error": "service unavailable"}"#)
            .expect(MAX_ATTEMPTS as usize)
            .create();

        let kms_client =
            HuaweiCloudKMS::new(&config).expect("create huaweicloud client should be successful");
        let request_url = format!("{}/kms/fake_endpoint", url);
        let fake_request = json!({"fake": "123"});

        let result = kms_client.do_request(&request_url, &fake_request).await;
        assert!(result.is_err(), "5xx should fail after retries exhausted");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("503"), "unexpected error: {}", err_msg);

        mock_auth.assert();
        mock_request.assert();
    }

    #[tokio::test]
    async fn test_kms_retry_on_5xx_eventually_succeeds() {
        let mut server = mockito::Server::new();
        let url = server.url();
        let config = get_kms_config(Some(url.clone()), Some(url.clone()));

        // Mock auth (called once)
        let mock_auth = server
            .mock("POST", "/v3/auth/tokens")
            .with_status(201)
            .with_header(AUTH_HEADER, "fake_auth_header")
            .expect(1)
            .create();

        // First two attempts 503, then 200 (mockito matches mocks in
        // registration order; each mock is consumed after expect(n) hits)
        let mock_fail = server
            .mock("POST", "/kms/fake_endpoint")
            .with_status(503)
            .with_body(r#"{"error": "service unavailable"}"#)
            .expect(2)
            .create();
        let mock_ok = server
            .mock("POST", "/kms/fake_endpoint")
            .with_status(200)
            .with_body(r#"{"key_id": "123", "plain_text_base64": "456", "plain_text": "decoded"}"#)
            .expect(1)
            .create();

        let kms_client =
            HuaweiCloudKMS::new(&config).expect("create huaweicloud client should be successful");
        let request_url = format!("{}/kms/fake_endpoint", url);
        let fake_request = json!({"fake": "123"});

        let result = kms_client.do_request(&request_url, &fake_request).await;
        assert!(result.is_ok(), "should succeed after retries: {:?}", result);

        mock_auth.assert();
        mock_fail.assert();
        mock_ok.assert();
    }

    #[tokio::test]
    async fn test_kms_no_retry_on_4xx() {
        let mut server = mockito::Server::new();
        let url = server.url();
        let config = get_kms_config(Some(url.clone()), Some(url.clone()));

        // Mock auth (called once)
        let mock_auth = server
            .mock("POST", "/v3/auth/tokens")
            .with_status(201)
            .with_header(AUTH_HEADER, "fake_auth_header")
            .expect(1)
            .create();

        // 400 Bad Request is a business error — must NOT be retried
        let mock_request = server
            .mock("POST", "/kms/fake_endpoint")
            .with_status(400)
            .with_body(r#"{"error": "invalid request"}"#)
            .expect(1)
            .create();

        let kms_client =
            HuaweiCloudKMS::new(&config).expect("create huaweicloud client should be successful");
        let request_url = format!("{}/kms/fake_endpoint", url);
        let fake_request = json!({"fake": "123"});

        let result = kms_client.do_request(&request_url, &fake_request).await;
        assert!(result.is_err(), "4xx should fail without retry");

        mock_auth.assert();
        mock_request.assert();
    }

    #[test]
    fn test_is_retryable_kms_error() {
        // network errors are retryable
        assert!(is_retryable_kms_error(&Error::HttpRequest(
            "connection refused".to_string()
        )));
        // 5xx status codes embedded in message are retryable
        for code in ["500", "502", "503", "504", "599"] {
            assert!(is_retryable_kms_error(&Error::KMSInvokeError(format!(
                "unable to encode/decode data in kms, result {} Service Unavailable",
                code
            ))));
        }
        // 4xx business errors are not retryable
        for code in ["400", "404", "429"] {
            assert!(!is_retryable_kms_error(&Error::KMSInvokeError(format!(
                "unable to encode/decode data in kms, result {} Bad Request",
                code
            ))));
        }
        // message containing "500" in a non-status-code context is not retryable
        assert!(!is_retryable_kms_error(&Error::KMSInvokeError(
            "request body exceeds 5000 bytes limit".to_string()
        )));
        // unrelated errors are not retryable
        assert!(!is_retryable_kms_error(&Error::ConfigError(
            "bad config".to_string()
        )));
    }

    #[tokio::test]
    async fn test_huaweicloud_request_timeout() {
        // auth endpoint responds quickly through mockito
        let mut iam_server = mockito::Server::new();
        let iam_url = iam_server.url();
        let mock_auth = iam_server
            .mock("POST", "/v3/auth/tokens")
            .with_status(201)
            .with_header(AUTH_HEADER, "fake_auth_header")
            .expect(1)
            .create();

        // kms endpoint accepts the connection but never responds, so only
        // the request timeout on the client side can abort the call
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let kms_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            // hold the connection open without sending any response
            std::future::pending::<()>().await;
        });

        //build the client with a short request timeout so the test does not
        //wait for the production default (30s); the production defaults are
        //wired in HuaweiCloudKMS::new
        let kms_client = HuaweiCloudKMS {
            kms_id: "fake_kms_id".to_string(),
            username: "fake_username".to_string(),
            password: SecUtf8::from("fake_password".to_string()),
            domain: "fake_domain".to_string(),
            project_name: "fake_project_name".to_string(),
            project_id: "fake_project_id".to_string(),
            iam_endpoint: iam_url,
            kms_endpoint: kms_url.clone(),
            auth_token_cache: Mutex::new("".to_string()),
            client: Client::builder()
                .timeout(Duration::from_millis(200))
                .build()
                .expect("create client should be successful"),
        };

        let start = std::time::Instant::now();
        //call do_request_once directly: this test verifies the timeout abort
        //itself, retry behaviour is covered by the dedicated retry tests
        let result = kms_client
            .do_request_once(&format!("{}/kms/fake_endpoint", kms_url), &json!({}))
            .await;

        //the request must be aborted by the client timeout
        assert!(
            matches!(result, Err(Error::HttpRequest(ref msg)) if msg.to_lowercase().contains("timed out"))
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        mock_auth.assert();
    }
}
