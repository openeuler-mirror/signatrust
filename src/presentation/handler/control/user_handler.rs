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
use crate::presentation::handler::control::model::token::dto::TokenDTO;

#[derive(Deserialize)]
struct Code {
    pub code: String,
}

/// Start the login OIDC login process
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl https://domain:port/api/v1/user/login
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/user/login",
    responses(
        (status = 302, description = "Redirect to login url"),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn login(user_service: web::Data<dyn UserService>) -> Result<impl Responder, Error> {
    Ok(HttpResponse::Found().insert_header(("Location", user_service.into_inner().get_login_url().await?.as_str())).finish())
}

/// Get login user information
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl https://domain:port/api/v1/user/
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/user/",
    responses(
        (status = 200, description = "get login user information", body = UserIdentity),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn info(id: UserIdentity) -> Result<impl Responder, Error> {
    Ok(HttpResponse::Ok().json(id))
}

/// Logout current user
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/user/logout
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/user/logout",
    responses(
        (status = 204, description = "logout successfully"),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn logout(id: Identity) -> Result<impl Responder, Error> {
    id.logout();
    Ok( HttpResponse::NoContent().finish())
}

/// Callback API for OIDC provider
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X GET https://domain:port/api/v1/user/callback
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/user/callback",
    responses(
    (status = 302, description = "logout succeed, redirect to index"),
    (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn callback(req: HttpRequest, user_service: web::Data<dyn UserService>, code: web::Query<Code>) -> Result<impl Responder, Error> {
    let user_entity:UserIdentity = UserIdentity::from(user_service.into_inner().validate_user(&code.code).await?);
    match Identity::login(&req.extensions(), serde_json::to_string(&user_entity)?) {
        Ok(_) => {
            Ok(HttpResponse::Found().insert_header(("Location", "/")).finish())
        }
        Err(err) => {
            Err(Error::AuthError(format!("failed to get oidc token {}", err)))
        }
    }
}

/// Generate new token for current user
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/user/api_keys
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/user/api_keys",
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 201, description = "logout successfully", body = TokenDTO),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn new_token(user: UserIdentity, user_service: web::Data<dyn UserService>, token: web::Json<TokenDTO>) -> Result<impl Responder, Error> {
    let token = user_service.into_inner().generate_token(&user, token.0).await?;
    Ok(HttpResponse::Created().json(TokenDTO::from(token)))
}

/// List all tokens for current user
///
/// **NOTE**: only the token hash will be responsed.
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X GET https://domain:port/api/v1/user/api_keys
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/user/api_keys",
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "logout successfully", body = [TokenDTO]),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn list_token(user: UserIdentity, user_service: web::Data<dyn UserService>) -> Result<impl Responder, Error> {
    let token = user_service.into_inner().get_token(&user).await?;
    let mut results = vec![];
    for t in token.into_iter() {
        results.push(TokenDTO::from(t));
    }
    Ok(HttpResponse::Ok().json(results))
}

pub fn get_scope() -> Scope {
    web::scope("/users")
        .service(web::resource("/").route(web::get().to(info)))
        .service(web::resource("/login").route(web::get().to(login)))
        .service(web::resource("/logout").route(web::post().to(logout)))
        .service(web::resource("/callback").route(web::get().to(callback)))
        .service(web::resource("/api_keys").route(web::post().to(new_token)).route(web::get().to(list_token)))
}