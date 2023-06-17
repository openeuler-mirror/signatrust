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

use crate::client::{sign_identity::SignIdentity};
use crate::client::worker::traits::SignHandler;
use crate::client::file_handler::traits::FileHandler;
use async_trait::async_trait;

pub mod signatrust {
    tonic::include_proto!("signatrust");
}

use tonic::transport::Channel;
use self::signatrust::{
    signatrust_client::SignatrustClient, SignStreamRequest,
};

use crate::util::error::Error;
use std::io::{Cursor, Read};

pub struct RemoteSigner {
    client: SignatrustClient<Channel>,
    buffer_size: usize,
}


impl RemoteSigner {

    pub fn new(channel: Channel, buffer_size: usize) -> Self {
        Self {
            client: SignatrustClient::new(channel),
            buffer_size,
        }
    }
}

#[async_trait]
impl SignHandler for RemoteSigner {
    async fn process(&mut self, _handler: Box<dyn FileHandler>, item: SignIdentity) -> SignIdentity {
        let mut signed_content = Vec::new();
        let read_data = item.raw_content.borrow().clone();
        for sign_content in read_data.into_iter() {
            let mut sign_segments: Vec<SignStreamRequest> = Vec::new();
            let mut buffer = vec![0; self.buffer_size];
            let mut cursor = Cursor::new(sign_content);
            while let Ok(length) = cursor.read(&mut buffer) {
                if length == 0 {
                    break
                }
                let content = buffer[0..length].to_vec();
                sign_segments.push(SignStreamRequest{
                    data: content,
                    options: item.sign_options.borrow().clone(),
                    key_type: format!("{}", item.key_type),
                    key_id: item.key_id.clone(),
                });
            }
            let result = self.client.sign_stream(
                tokio_stream::iter(sign_segments)).await;
            match result {
                Ok(result) => {
                    let data = result.into_inner();
                    if data.error.is_empty() {
                        signed_content.push(data.signature);
                    } else {
                        *item.error.borrow_mut() = Err(Error::RemoteSignError(data.error))
                    }
                }
                Err(err) => {
                    *item.error.borrow_mut() = Err(Error::RemoteSignError(format!("{:?}", err)))
                }
            }
        }
        debug!("successfully sign file {}", item.file_path.as_path().display());
        *item.signature.borrow_mut() = signed_content;
        //clear out temporary value
        *item.raw_content.borrow_mut() = Vec::new();
        item
    }
}

