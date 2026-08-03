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

use crate::client::file_handler::traits::FileHandler;
use crate::client::sign_identity::SignIdentity;
use crate::client::worker::traits::SignHandler;
use async_trait::async_trait;

pub mod signatrust {
    tonic::include_proto!("signatrust");
}

use self::signatrust::{signatrust_client::SignatrustClient, SignStreamRequest};
use tonic::transport::Channel;

use crate::util::error::Error;
use std::io::{Cursor, Read};

/// Maximum retry attempts for gRPC sign_stream calls.
const MAX_RETRIES: u32 = 3;
/// Initial backoff in milliseconds.
const INITIAL_BACKOFF_MS: u64 = 100;

pub struct RemoteSigner {
    client: SignatrustClient<Channel>,
    buffer_size: usize,
    token: Option<String>,
}

impl RemoteSigner {
    pub fn new(channel: Channel, buffer_size: usize, token: Option<String>) -> Self {
        Self {
            client: SignatrustClient::new(channel),
            buffer_size,
            token,
        }
    }
}

#[async_trait]
impl SignHandler for RemoteSigner {
    async fn process(
        &mut self,
        _handler: Box<dyn FileHandler>,
        item: SignIdentity,
    ) -> SignIdentity {
        let mut signed_content = Vec::new();
        let read_data = item.raw_content.borrow().clone();
        for sign_content in read_data.into_iter() {
            let mut sign_segments: Vec<SignStreamRequest> = Vec::new();
            let mut buffer = vec![0; self.buffer_size];
            let mut cursor = Cursor::new(sign_content);
            while let Ok(length) = cursor.read(&mut buffer) {
                if length == 0 {
                    break;
                }
                let content = buffer[0..length].to_vec();
                sign_segments.push(SignStreamRequest {
                    data: content,
                    options: item.sign_options.borrow().clone(),
                    key_type: format!("{}", item.key_type),
                    key_id: item.key_id.clone(),
                    token: self.token.clone(),
                });
            }
            if sign_segments.is_empty() {
                *item.error.borrow_mut() = Err(Error::FileContentEmpty);
                return item;
            }

            // Retry gRPC sign_stream with exponential backoff
            let mut last_err = None;
            for attempt in 0..=MAX_RETRIES {
                if attempt > 0 {
                    let backoff_ms = INITIAL_BACKOFF_MS * 2u64.pow(attempt - 1);
                    debug!(
                        "gRPC sign_stream retry {}/{}, backoff {}ms",
                        attempt, MAX_RETRIES, backoff_ms
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                }
                let result = self
                    .client
                    .sign_stream(tokio_stream::iter(sign_segments.clone()))
                    .await;
                match result {
                    Ok(resp) => {
                        let data = resp.into_inner();
                        if data.error.is_empty() {
                            signed_content.push(data.signature);
                            last_err = None;
                            break;
                        }
                        // Server-side error — not retryable
                        *item.error.borrow_mut() = Err(Error::RemoteSignError(data.error));
                        return item;
                    }
                    Err(e) => {
                        let err_str = format!("{:?}", e);
                        debug!("sign_stream attempt {} failed: {}", attempt + 1, err_str);
                        last_err = Some(err_str);
                    }
                }
            }
            if let Some(err) = last_err {
                *item.error.borrow_mut() = Err(Error::RemoteSignError(format!(
                    "sign_stream failed after {} retries: {}",
                    MAX_RETRIES + 1,
                    err
                )));
                return item;
            }
        }
        debug!(
            "successfully sign file {}",
            item.file_path.as_path().display()
        );
        *item.signature.borrow_mut() = signed_content;
        //clear out temporary value
        *item.raw_content.borrow_mut() = Vec::new();
        item
    }
}
