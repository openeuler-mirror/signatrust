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

/// Maximum total attempts for gRPC sign_stream calls (including initial call).
const MAX_ATTEMPTS: u32 = 4;
/// Initial backoff in milliseconds for gRPC retries.
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

            // Retry gRPC sign_stream with exponential backoff on transient
            // errors only. Server-side business errors (non-empty error field
            // in the response) and deterministic gRPC errors (e.g. permission
            // denied) fail fast without retry.
            for attempt in 1..=MAX_ATTEMPTS {
                if attempt > 1 {
                    let backoff_ms = INITIAL_BACKOFF_MS * 2u64.pow(attempt - 2);
                    debug!(
                        "gRPC sign_stream attempt {}/{}, backoff {}ms",
                        attempt, MAX_ATTEMPTS, backoff_ms
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
                            break;
                        }
                        // Server-side business error — not retryable
                        *item.error.borrow_mut() = Err(Error::RemoteSignError(data.error));
                        return item;
                    }
                    Err(e) => {
                        if !is_retryable_grpc_status(&e) {
                            *item.error.borrow_mut() = Err(Error::RemoteSignError(format!(
                                "sign_stream failed at attempt {}: {:?}",
                                attempt, e
                            )));
                            return item;
                        }
                        if attempt == MAX_ATTEMPTS {
                            *item.error.borrow_mut() = Err(Error::RemoteSignError(format!(
                                "sign_stream failed after {} attempts: {:?}",
                                MAX_ATTEMPTS, e
                            )));
                            return item;
                        }
                        debug!(
                            "sign_stream attempt {} failed (retryable): {:?}",
                            attempt, e
                        );
                    }
                }
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

/// Returns true for transient gRPC status codes that are worth retrying.
/// Transport failures (connection refused, broken pipe, timeout, server
/// overload) surface as Unavailable/Unknown/DeadlineExceeded/
/// ResourceExhausted. Deterministic errors such as PermissionDenied or
/// InvalidArgument fail fast instead of wasting retry latency.
fn is_retryable_grpc_status(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unavailable
            | tonic::Code::Unknown
            | tonic::Code::DeadlineExceeded
            | tonic::Code::ResourceExhausted
    )
}

#[cfg(test)]
mod tests {
    use super::signatrust::{
        signatrust_server::{Signatrust, SignatrustServer},
        GetKeyInfoRequest, GetKeyInfoResponse, SignStreamRequest, SignStreamResponse,
    };
    use super::*;
    use crate::util::sign::{FileType, KeyType};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::oneshot;
    use tonic::transport::server::TcpIncoming;
    use tonic::{Code, Request, Response, Status};

    /// Mock gRPC service. The first `fail_times` sign_stream calls return a
    /// gRPC error with the given `fail_status` code; subsequent calls succeed.
    /// When `business_error` is non-empty, every call returns that server-side
    /// business error instead.
    struct MockSignService {
        calls: Arc<AtomicUsize>,
        fail_times: usize,
        fail_status: Code,
        business_error: String,
        signature: Vec<u8>,
    }

    impl MockSignService {
        fn new(
            fail_times: usize,
            fail_status: Code,
            business_error: &str,
            signature: Vec<u8>,
        ) -> (Arc<AtomicUsize>, Self) {
            let calls = Arc::new(AtomicUsize::new(0));
            let service = Self {
                calls: calls.clone(),
                fail_times,
                fail_status,
                business_error: business_error.to_string(),
                signature,
            };
            (calls, service)
        }
    }

    #[async_trait::async_trait]
    impl Signatrust for MockSignService {
        async fn get_key_info(
            &self,
            _request: Request<GetKeyInfoRequest>,
        ) -> Result<Response<GetKeyInfoResponse>, Status> {
            Ok(Response::new(GetKeyInfoResponse::default()))
        }

        async fn sign_stream(
            &self,
            _request: Request<tonic::Streaming<SignStreamRequest>>,
        ) -> Result<Response<SignStreamResponse>, Status> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if !self.business_error.is_empty() {
                return Ok(Response::new(SignStreamResponse {
                    signature: vec![],
                    error: self.business_error.clone(),
                }));
            }
            if call <= self.fail_times {
                return Err(Status::new(self.fail_status, "mock failure"));
            }
            Ok(Response::new(SignStreamResponse {
                signature: self.signature.clone(),
                error: String::new(),
            }))
        }
    }

    /// Start the mock gRPC server on an ephemeral port, returning its address
    /// and the shared call counter.
    async fn start_mock_server(service: MockSignService) -> (String, Arc<AtomicUsize>) {
        let calls = service.calls.clone();
        let (addr_tx, addr_rx) = oneshot::channel();
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            addr_tx.send(addr).unwrap();
            let incoming = TcpIncoming::from_listener(listener, true, None).unwrap();
            tonic::transport::Server::builder()
                .add_service(SignatrustServer::new(service))
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        (format!("http://{}", addr_rx.await.unwrap()), calls)
    }

    fn build_identity(content: Vec<u8>) -> SignIdentity {
        let identity = SignIdentity::new(
            FileType::Rpm,
            PathBuf::from("/tmp/fake.rpm"),
            KeyType::Pgp,
            "fake-key-id".to_string(),
            HashMap::new(),
        );
        *identity.raw_content.borrow_mut() = vec![content];
        identity
    }

    struct MockFileHandler;

    #[async_trait::async_trait]
    impl FileHandler for MockFileHandler {
        fn validate_options(
            &self,
            _sign_options: &mut HashMap<String, String>,
        ) -> crate::util::error::Result<()> {
            Ok(())
        }

        async fn assemble_data(
            &self,
            _path: &PathBuf,
            _data: Vec<Vec<u8>>,
            _temp_dir: &PathBuf,
            _sign_options: &HashMap<String, String>,
            _key_attributes: &HashMap<String, String>,
        ) -> crate::util::error::Result<(String, String)> {
            Ok(("fake".to_string(), "fake".to_string()))
        }
    }

    #[tokio::test]
    async fn test_sign_stream_retry_on_transport_error_then_succeed() {
        let signature = b"signed-data".to_vec();
        let (_, service) = MockSignService::new(2, Code::Unavailable, "", signature.clone());
        let (addr, calls) = start_mock_server(service).await;
        let channel = Channel::from_shared(addr).unwrap().connect().await.unwrap();
        // Small buffer size forces multiple segments, verifying that retried
        // calls re-send every cloned segment.
        let mut signer = RemoteSigner::new(channel, 4, None);
        let item = build_identity(b"hello world".to_vec());
        let result = signer.process(Box::new(MockFileHandler), item).await;
        assert!(result.error.borrow().is_ok());
        assert_eq!(*result.signature.borrow(), vec![signature]);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_sign_stream_no_retry_on_business_error() {
        let (_, service) = MockSignService::new(0, Code::Unavailable, "key not found", vec![]);
        let (addr, calls) = start_mock_server(service).await;
        let channel = Channel::from_shared(addr).unwrap().connect().await.unwrap();
        let mut signer = RemoteSigner::new(channel, 1024, None);
        let item = build_identity(b"hello world".to_vec());
        let result = signer.process(Box::new(MockFileHandler), item).await;
        assert!(matches!(
            result.error.borrow().clone(),
            Err(Error::RemoteSignError(msg)) if msg == "key not found"
        ));
        assert!(result.signature.borrow().is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_sign_stream_retry_exhausted_after_max_attempts() {
        let (_, service) =
            MockSignService::new(MAX_ATTEMPTS as usize, Code::Unavailable, "", vec![]);
        let (addr, calls) = start_mock_server(service).await;
        let channel = Channel::from_shared(addr).unwrap().connect().await.unwrap();
        let mut signer = RemoteSigner::new(channel, 1024, None);
        let item = build_identity(b"hello world".to_vec());
        let result = signer.process(Box::new(MockFileHandler), item).await;
        assert!(matches!(
            result.error.borrow().clone(),
            Err(Error::RemoteSignError(msg)) if msg.contains("after 4 attempts")
        ));
        assert!(result.signature.borrow().is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), MAX_ATTEMPTS as usize);
    }

    #[tokio::test]
    async fn test_sign_stream_no_retry_on_non_retryable_status() {
        let (_, service) =
            MockSignService::new(MAX_ATTEMPTS as usize, Code::PermissionDenied, "", vec![]);
        let (addr, calls) = start_mock_server(service).await;
        let channel = Channel::from_shared(addr).unwrap().connect().await.unwrap();
        let mut signer = RemoteSigner::new(channel, 1024, None);
        let item = build_identity(b"hello world".to_vec());
        let result = signer.process(Box::new(MockFileHandler), item).await;
        assert!(matches!(
            result.error.borrow().clone(),
            Err(Error::RemoteSignError(msg)) if msg.contains("failed at attempt 1")
        ));
        assert!(result.signature.borrow().is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
