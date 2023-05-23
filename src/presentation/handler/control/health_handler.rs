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

use actix_web::{HttpResponse, Responder, Result, web, Scope};
use crate::util::error::Error;

use crate::application::user::UserService;

/// Get the server health status
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl https://domain:port/api/health/
/// ```
#[utoipa::path(
    get,
    path = "/api/health/",
    responses(
        (status = 200, description = "Server is healthy"),
        (status = 500, description = "Server is Unhealthy", body = ErrorMessage)
    )
)]
async fn health(_user_service: web::Data<dyn UserService>) -> Result<impl Responder, Error> {
    Ok(HttpResponse::Ok())
}

pub fn get_scope() -> Scope {
    web::scope("/health")
        .service(web::resource("/").route(web::get().to(health)))
}