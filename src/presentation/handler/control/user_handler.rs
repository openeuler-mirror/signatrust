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

async fn login(user_service: web::Data<dyn UserService>) -> Result<impl Responder, Error> {
    Ok(HttpResponse::Found().insert_header(("Location", user_service.into_inner().get_login_url().await?.as_str())).finish())
}

async fn info(id: UserIdentity) -> Result<impl Responder, Error> {
    Ok(HttpResponse::Ok().json(id))
}

async fn logout(id: Identity) -> Result<impl Responder, Error> {
    id.logout();
    Ok( HttpResponse::NoContent().finish())
}

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

async fn new_token(user: UserIdentity, user_service: web::Data<dyn UserService>, token: web::Json<TokenDTO>) -> Result<impl Responder, Error> {
    let token = user_service.into_inner().generate_token(&user, token.0).await?;
    Ok(HttpResponse::Ok().json(TokenDTO::from(token)))
}

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