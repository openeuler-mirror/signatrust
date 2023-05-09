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

use actix_web::{HttpResponse, Responder, Result, web, Scope, HttpRequest, HttpMessage};
use serde::{Deserialize};
use crate::util::error::Error;
use super::model::user::dto::UserIdentity;
use actix_identity::Identity;

use crate::application::user::UserService;
use crate::presentation::handler::control::model::token::dto::{CreateTokenDTO, TokenDTO};

#[derive(Deserialize)]
struct Code {
    pub code: String,
}

/// Get the server health status
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl https://domain:port/api/v1/health/
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/health",
    responses(
        (status = 200, description = "Server is healthy"),
        (status = 500, description = "Server is Unhealthy", body = ErrorMessage)
    )
)]
async fn health(user_service: web::Data<dyn UserService>) -> Result<impl Responder, Error> {
    Ok(HttpResponse::Found().insert_header(("Location", user_service.into_inner().get_login_url().await?.as_str())).finish())
}

pub fn get_scope() -> Scope {
    web::scope("/health")
        .service(web::resource("/").route(web::get().to(health)))
}