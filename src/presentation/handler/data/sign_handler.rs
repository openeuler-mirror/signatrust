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

pub mod signatrust {
    tonic::include_proto!("signatrust");
}
use tokio_stream::StreamExt;

use crate::application::datakey::KeyService;
use crate::application::user::UserService;
use crate::domain::datakey::entity::KeyType::X509EE;
use crate::util::error::Error;
use crate::util::error::Result as SignatrustResult;
use openssl::x509::X509;
use signatrust::{
    signatrust_server::Signatrust, signatrust_server::SignatrustServer, GetKeyInfoRequest,
    GetKeyInfoResponse, SignStreamRequest, SignStreamResponse,
};
use std::collections::HashMap;
use tonic::{Request, Response, Status, Streaming};

const SUBJECT_KEY_ID: &str = "subject_key";

pub struct SignHandler<K, U>
where
    K: KeyService + 'static,
    U: UserService + 'static,
{
    key_service: K,
    user_service: U,
}

impl<K, U> SignHandler<K, U>
where
    K: KeyService + 'static,
    U: UserService + 'static,
{
    pub fn new(key_service: K, user_service: U) -> Self {
        SignHandler {
            key_service,
            user_service,
        }
    }
    async fn validate_key_token_matched(
        &self,
        token: Option<String>,
        name: &str,
    ) -> SignatrustResult<()> {
        let names: Vec<_> = name.split(':').collect();
        if names.len() <= 1 {
            return Ok(());
        }
        if token.is_none()
            || !self
                .user_service
                .validate_token_and_email(names[0], &token.unwrap())
                .await?
        {
            return Err(Error::AuthError(
                "user token and email unmatched".to_string(),
            ));
        }
        Ok(())
    }
}

/// Collect a complete sign request from the incoming stream. Stream errors
/// (e.g. client disconnect or protocol error) are reported as errors instead
/// of panics, since sign_stream is an open entry point of the data plane.
async fn collect_sign_request<S>(
    binaries: &mut S,
) -> SignatrustResult<(
    Vec<u8>,
    String,
    String,
    HashMap<String, String>,
    Option<String>,
)>
where
    S: tokio_stream::Stream<Item = std::result::Result<SignStreamRequest, Status>> + Unpin,
{
    let mut data: Vec<u8> = vec![];
    let mut key_name: String = "".to_string();
    let mut key_type: String = "".to_string();
    let mut options: HashMap<String, String> = HashMap::new();
    let mut token: Option<String> = None;
    while let Some(content) = binaries.next().await {
        let mut inner_result = content.map_err(|err| {
            Error::ParameterError(format!("failed to receive sign request: {}", err))
        })?;
        data.append(&mut inner_result.data);
        key_name = inner_result.key_id;
        key_type = inner_result.key_type;
        options = inner_result.options;
        token = inner_result.token;
    }
    Ok((data, key_name, key_type, options, token))
}

/// Extract the subject key identifier from an X509 certificate in PEM
/// format, reporting malformed certificates as errors instead of panics.
fn extract_subject_key_id(certificate: &[u8]) -> SignatrustResult<String> {
    let x509 = X509::from_pem(certificate).map_err(|err| {
        Error::KeyParseError(format!("can not get certificate from PEM: {}", err))
    })?;
    let skid_pem = x509
        .subject_key_id()
        .ok_or_else(|| Error::KeyParseError("get subject key id failed".to_string()))?;
    Ok(hex::encode(skid_pem.as_slice()))
}

#[tonic::async_trait]
impl<K, U> Signatrust for SignHandler<K, U>
where
    K: KeyService + 'static,
    U: UserService + 'static,
{
    async fn get_key_info(
        &self,
        request: Request<GetKeyInfoRequest>,
    ) -> Result<Response<GetKeyInfoResponse>, Status> {
        let request = request.into_inner();
        //perform token validation on private keys
        if let Err(err) = self
            .validate_key_token_matched(request.token, &request.key_id)
            .await
        {
            return Ok(Response::new(GetKeyInfoResponse {
                attributes: HashMap::new(),
                error: err.to_string(),
            }));
        }
        let key_id_or_name = request.key_id.to_string();
        return match self
            .key_service
            .get_by_type_and_name(Some(request.key_type), request.key_id)
            .await
        {
            Ok(datakey) => {
                let mut new_info = datakey.attributes.clone();
                if datakey.key_type == X509EE {
                    // need get decode datakey
                    let public_datakey = match self.key_service.get_inner_one(key_id_or_name).await
                    {
                        Ok(public) => public,
                        Err(err) => {
                            return Ok(Response::new(GetKeyInfoResponse {
                                attributes: HashMap::new(),
                                error: err.to_string(),
                            }))
                        }
                    };
                    let skid_hex = match extract_subject_key_id(&public_datakey.certificate) {
                        Ok(skid) => skid,
                        Err(err) => {
                            return Ok(Response::new(GetKeyInfoResponse {
                                attributes: HashMap::new(),
                                error: err.to_string(),
                            }))
                        }
                    };
                    new_info.insert(SUBJECT_KEY_ID.to_string(), skid_hex.clone());
                    debug!("SKID (hex): {}", skid_hex);
                }
                Ok(Response::new(GetKeyInfoResponse {
                    attributes: new_info,
                    error: "".to_string(),
                }))
            }
            Err(err) => Ok(Response::new(GetKeyInfoResponse {
                attributes: HashMap::new(),
                error: err.to_string(),
            })),
        };
    }

    async fn sign_stream(
        &self,
        request: Request<Streaming<SignStreamRequest>>,
    ) -> Result<Response<SignStreamResponse>, Status> {
        let mut binaries = request.into_inner();
        let (data, key_name, key_type, options, token) =
            match collect_sign_request(&mut binaries).await {
                Ok(result) => result,
                Err(err) => {
                    return Ok(Response::new(SignStreamResponse {
                        signature: vec![],
                        error: err.to_string(),
                    }))
                }
            };
        //perform token validation on private keys
        if let Err(err) = self.validate_key_token_matched(token, &key_name).await {
            return Ok(Response::new(SignStreamResponse {
                signature: vec![],
                error: err.to_string(),
            }));
        }
        debug!(
            "begin to sign key_type :{} key_name: {}",
            key_type, key_name
        );
        match self
            .key_service
            .sign(key_type, key_name, &options, data)
            .await
        {
            Ok(content) => Ok(Response::new(SignStreamResponse {
                signature: content,
                error: "".to_string(),
            })),
            Err(err) => Ok(Response::new(SignStreamResponse {
                signature: vec![],
                error: err.to_string(),
            })),
        }
    }
}

pub fn get_grpc_handler<K, U>(
    key_service: K,
    user_service: U,
) -> SignatrustServer<SignHandler<K, U>>
where
    K: KeyService + 'static,
    U: UserService + 'static,
{
    let app = SignHandler::new(key_service, user_service);
    SignatrustServer::new(app)
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_collect_sign_request_successful() {
        let mut stream = tokio_stream::iter(vec![
            Ok(SignStreamRequest {
                data: b"hello ".to_vec(),
                options: HashMap::new(),
                key_type: "pgp".to_string(),
                key_id: "fake-key".to_string(),
                token: Some("fake-token".to_string()),
            }),
            Ok(SignStreamRequest {
                data: b"world".to_vec(),
                options: HashMap::new(),
                key_type: "pgp".to_string(),
                key_id: "fake-key".to_string(),
                token: Some("fake-token".to_string()),
            }),
        ]);
        let (data, key_name, key_type, options, token) = collect_sign_request(&mut stream)
            .await
            .expect("collect should succeed");
        assert_eq!(data, b"hello world".to_vec());
        assert_eq!(key_name, "fake-key");
        assert_eq!(key_type, "pgp");
        assert!(options.is_empty());
        assert_eq!(token, Some("fake-token".to_string()));
    }

    #[tokio::test]
    async fn test_collect_sign_request_stream_error() {
        // a client disconnect or protocol error surfaces as a stream error,
        // which must be reported instead of panicking the data plane
        let mut stream = tokio_stream::iter(vec![Err(Status::internal("connection broken"))]);
        let result = collect_sign_request(&mut stream).await;
        assert!(matches!(result, Err(Error::ParameterError(_))));
    }

    #[test]
    fn test_extract_subject_key_id_invalid_pem() {
        let result = extract_subject_key_id(b"not a pem certificate");
        assert!(matches!(
            result,
            Err(Error::KeyParseError(ref msg)) if msg.contains("can not get certificate from PEM")
        ));
    }

    #[test]
    fn test_extract_subject_key_id_missing_extension() {
        // the test certificate has no subject key identifier extension,
        // which must be reported instead of panicking
        let certificate = std::fs::read("test_assets/rsa_test_cert.pem")
            .expect("read test certificate should be successful");
        let result = extract_subject_key_id(&certificate);
        assert!(matches!(
            result,
            Err(Error::KeyParseError(ref msg)) if msg.contains("get subject key id failed")
        ));
    }
}
