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

pub mod signatrust {
    tonic::include_proto!("signatrust");
}
use tokio_stream::StreamExt;

use signatrust::{
    signatrust_server::Signatrust, signatrust_server::SignatrustServer, SignStreamRequest,
    SignStreamResponse, GetKeyInfoRequest, GetKeyInfoResponse
};
use tonic::{Request, Response, Status, Streaming};
use crate::application::datakey::KeyService;
use crate::application::user::UserService;
use crate::util::error::Error;
use crate::util::error::Result as SignatrustResult;

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
            user_service
        }
    }
    async fn validate_key_token_matched(&self, token: Option<String>, name: &str) -> SignatrustResult<()> {
        let names: Vec<_> = name.split(':').collect();
        if names.len() <= 1 {
            return Ok(())
        }
        if token.is_none() || !self.user_service.validate_token_and_email(names[0], &token.unwrap()).await? {
            return Err(Error::AuthError("user token and email unmatched".to_string()))
        }
        Ok(())
    }
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
    ) -> Result<Response<GetKeyInfoResponse>, Status>
    {
        let request = request.into_inner();
        //perform token validation on private keys
        if let Err(err) = self.validate_key_token_matched(request.token, &request.key_id).await {
            return Ok(Response::new(GetKeyInfoResponse {
                attributes: HashMap::new(),
                error: err.to_string(),
            }))
        }
        return match self.key_service.get_by_type_and_name(request.key_type, request.key_id).await {
            Ok(datakey) => {
                Ok(Response::new(GetKeyInfoResponse {
                    attributes: datakey.attributes,
                    error: "".to_string(),
                }))
            }
            Err(err) => {
                Ok(Response::new(GetKeyInfoResponse {
                    attributes: HashMap::new(),
                    error: err.to_string(),
                }))
            }
        }
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
            }))
        }
        debug!("begin to sign key_type :{} key_name: {}", key_type, key_name);
        match self.key_service.sign(key_type, key_name, &options, data).await {
            Ok(content) => {
                Ok(Response::new(SignStreamResponse {
                    signature: content,
                    error: "".to_string()
                }))
            }
            Err(err) => {
                Ok(Response::new(SignStreamResponse {
                    signature: vec![],
                    error: err.to_string(),
                }))
            }
        }
    }
}

pub fn get_grpc_handler<K, U>(key_service: K, user_service: U) -> SignatrustServer<SignHandler<K, U>>
where
    K: KeyService + 'static,
    U: UserService + 'static
{
    let app = SignHandler::new(key_service, user_service);
    SignatrustServer::new(app)
}
