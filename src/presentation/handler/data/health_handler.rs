/*
 * // Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 * //
 * // signatrust is licensed under Mulan PSL v2.
 * // You can use this software according to the terms and conditions of the Mulan
 * // PSL v2.
 * // You may obtain a copy of Mulan PSL v2 at:
 * //         http://license.coscl.org.cn/MulanPSL2
 * // THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * // KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * // NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * // See the Mulan PSL v2 for more details.
 */

use std::pin::Pin;
pub mod health {
    tonic::include_proto!("grpc.health.v1");
}
use tokio_stream::{Stream, once};

use health::{
    health_server::Health, health_server::HealthServer, HealthCheckRequest, HealthCheckResponse, health_check_response::ServingStatus,
};
use tonic::{Request, Response, Status};

type ResponseStream = Pin<Box<dyn Stream<Item = Result<HealthCheckResponse, Status>> + Send>>;

pub struct HealthHandler {}

impl HealthHandler {
    pub fn new() -> Self {
        HealthHandler {}
    }
}

#[tonic::async_trait]
impl Health for HealthHandler
{
    type WatchStream = ResponseStream;
    async fn check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let reply = HealthCheckResponse {
            status: ServingStatus::Serving as i32,
        };
        Ok(Response::new(reply))
    }
    async fn watch(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        //reply result stream once
        let reply = HealthCheckResponse {
            status: ServingStatus::Serving as i32,
        };
        let reply_stream = once(Ok(reply));
        Ok(Response::new(Box::pin(reply_stream)))
    }

}

pub fn get_grpc_handler() -> HealthServer<HealthHandler>
{
    let app = HealthHandler::new();
    HealthServer::new(app)
}
