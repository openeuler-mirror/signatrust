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
use crate::util::error::Error;
use super::model::user::dto::UserIdentity;
use actix_identity::Identity;
use validator::Validate;

use crate::application::user::UserService;
use crate::presentation::handler::control::model::token::dto::{CreateTokenDTO, TokenDTO};
use crate::presentation::handler::control::model::user::dto::Code;

/// Start the login OIDC login process
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl https://domain:port/api/v1/users/login
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/users/login",
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
/// curl https://domain:port/api/v1/users/
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/users/",
    security(
        ("Authorization" = [])
    ),
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
/// curl -X POST https://domain:port/api/v1/users/logout
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/users/logout",
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
/// curl -X GET https://domain:port/api/v1/users/callback
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/users/callback",
    params(
        Code
    ),
    responses(
    (status = 302, description = "logout succeed, redirect to index"),
    (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn callback(req: HttpRequest, user_service: web::Data<dyn UserService>, code: web::Query<Code>) -> Result<impl Responder, Error> {
    code.validate()?;
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
/// curl -X POST https://domain:port/api/v1/users/api_keys
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/users/api_keys",
    request_body = CreateTokenDTO,
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 201, description = "logout successfully", body = TokenDTO),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn new_token(user: UserIdentity, user_service: web::Data<dyn UserService>, token: web::Json<CreateTokenDTO>) -> Result<impl Responder, Error> {
    let token = user_service.into_inner().generate_token(&user, token.0).await?;
    Ok(HttpResponse::Created().json(TokenDTO::from(token)))
}

/// Delete specified user token
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X DELETE https://domain:port/api/v1/users/api_keys/{id}
/// ```
#[utoipa::path(
    delete,
    path = "/api/v1/users/api_keys/{id}",
    params(
        ("id" = i32, Path, description = "Token id"),
    ),
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Token successfully deleted"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn delete_token(user: UserIdentity, user_service: web::Data<dyn UserService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    user_service.into_inner().delete_token(&user, id.parse::<i32>()?).await?;
    Ok(HttpResponse::Ok())
}

/// List all tokens for current user
///
/// **NOTE**: only the token hash will be responded.
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X GET https://domain:port/api/v1/users/api_keys
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/users/api_keys",
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
        .service(web::resource("/api_keys")
            .route(web::post().to(new_token))
            .route(web::get().to(list_token)))
        .service( web::resource("/api_keys/{id}")
            .route(web::delete().to(delete_token)))
}