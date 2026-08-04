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

use actix_web::{web, HttpResponse, Responder, Scope};

use crate::util::metrics;

/// GET /api/metrics — expose Prometheus text-format metrics.
async fn metrics_handler() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(metrics::gather_metrics())
}

pub fn get_scope() -> Scope {
    web::scope("/metrics").service(web::resource("/").route(web::get().to(metrics_handler)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_web::test]
    async fn test_metrics_endpoint_returns_200() {
        let app = test::init_service(App::new().service(get_scope())).await;
        let req = test::TestRequest::get().uri("/metrics/").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_metrics_endpoint_has_content_type() {
        let app = test::init_service(App::new().service(get_scope())).await;
        let req = test::TestRequest::get().uri("/metrics/").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "text/plain; version=0.0.4"
        );
    }
}
