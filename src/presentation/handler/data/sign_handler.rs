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
        validate_key_token_for_name(name, token, &self.user_service).await
    }
}

/// Extract token validation logic for the named key into a pure function
/// that takes a name (possibly in "email:keyname" format), an optional token,
/// and a UserService reference. Non-async logic runs first.
pub(crate) fn parse_key_name_parts(name: &str) -> (&str, Option<&str>) {
    let parts: Vec<&str> = name.split(':').collect();
    if parts.len() > 1 {
        (parts[1], Some(parts[0]))
    } else {
        (name, None)
    }
}

pub(crate) async fn validate_key_token_for_name<U: UserService + 'static>(
    name: &str,
    token: Option<String>,
    user_service: &U,
) -> SignatrustResult<()> {
    let (_key_name, email_opt) = parse_key_name_parts(name);
    if let Some(email) = email_opt {
        let token_value = token
            .ok_or_else(|| Error::AuthError("user token required for private key".to_string()))?;
        if !user_service
            .validate_token_and_email(email, &token_value)
            .await?
        {
            return Err(Error::AuthError(
                "user token and email unmatched".to_string(),
            ));
        }
    }
    Ok(())
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
                    let x509 = X509::from_pem(&public_datakey.certificate)
                        .expect("can not get certificate from PEM");
                    let skid_pem = x509.subject_key_id().expect("get subject key id failed");
                    let skid_vec = skid_pem.as_slice();
                    new_info.insert(SUBJECT_KEY_ID.to_string(), hex::encode(skid_vec));
                    debug!("SKID (hex): {}", hex::encode(skid_vec));
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
        let mut data: Vec<u8> = vec![];
        let mut key_name: String = "".to_string();
        let mut key_type: String = "".to_string();
        let mut options: HashMap<String, String> = HashMap::new();
        let mut token: Option<String> = None;
        while let Some(content) = binaries.next().await {
            let mut inner_result = content.unwrap();
            data.append(&mut inner_result.data);
            key_name = inner_result.key_id;
            key_type = inner_result.key_type;
            options = inner_result.options;
            token = inner_result.token;
        }
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
mod tests {
    use super::parse_key_name_parts;

    #[test]
    fn test_parse_key_name_parts_no_colon() {
        let (key_name, email) = parse_key_name_parts("my-pgp-key");
        assert_eq!(key_name, "my-pgp-key");
        assert_eq!(email, None);
    }

    #[test]
    fn test_parse_key_name_parts_with_email_prefix() {
        let (key_name, email) = parse_key_name_parts("user@example.com:my-pgp-key");
        assert_eq!(key_name, "my-pgp-key");
        assert_eq!(email, Some("user@example.com"));
    }

    #[test]
    fn test_parse_key_name_parts_multiple_colons() {
        let (key_name, email) = parse_key_name_parts("user@example.com:my-pgp-key:extra");
        assert_eq!(key_name, "my-pgp-key");
        assert_eq!(email, Some("user@example.com"));
    }

    #[test]
    fn test_parse_key_name_parts_empty_name() {
        let (key_name, email) = parse_key_name_parts("");
        assert_eq!(key_name, "");
        assert_eq!(email, None);
    }

    #[test]
    fn test_parse_key_name_parts_only_colon() {
        let (key_name, email) = parse_key_name_parts(":");
        assert_eq!(key_name, "");
        assert_eq!(email, Some(""));
    }

    #[test]
    fn test_parse_key_name_parts_trailing_colon() {
        let (key_name, email) = parse_key_name_parts("email@test.com:");
        assert_eq!(key_name, "");
        assert_eq!(email, Some("email@test.com"));
    }
}
