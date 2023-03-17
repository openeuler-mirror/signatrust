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

use actix_web::{HttpResponse, Responder, Result, web, Scope, HttpRequest, HttpMessage};

use serde::{Deserialize};

use crate::util::error::Error;
use super::model::user::dto::UserIdentity;
use actix_identity::Identity;

use openidconnect::{
    AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce,
    OAuth2TokenResponse, core::CoreResponseType, core::CoreClient
};

use crate::model::user::repository::Repository as userRepository;
use reqwest::{header, Client};
use openidconnect::Scope as OIDCScore;
use openidconnect::reqwest::async_http_client;
use crate::infra::database::model::token::repository::TokenRepository;
use crate::infra::database::model::user::repository::UserRepository;
use crate::model::token::entity::Token;
use crate::model::token::repository::Repository as tokenRepository;
use crate::model::user::entity::User;
use crate::service::control_service::model::token::dto::TokenDTO;

#[derive(Deserialize)]
struct Code {
    pub code: String,
}

#[derive(Deserialize)]
pub struct UserEmail {
    pub email: String,
}

async fn login(client: web::Data<CoreClient>) -> Result<impl Responder, Error> {
    let (authorize_url, _, _) = client
        .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                       CsrfToken::new_random, Nonce::new_random, )
        .add_scope(OIDCScore::new("email".to_string()))
        .add_scope(OIDCScore::new("openid".to_string()))
        .add_scope(OIDCScore::new("profile".to_string()))
        .url();
    Ok(HttpResponse::Found().insert_header(("Location", authorize_url.as_str())).finish())
}

async fn info(user: UserIdentity) -> Result<impl Responder, Error> {
    Ok(HttpResponse::Ok().json(user))
}

async fn logout(id: Identity) -> Result<impl Responder, Error> {
    id.logout();
    Ok( HttpResponse::NoContent().finish())
}

async fn callback(req: HttpRequest, client: web::Data<CoreClient>, user_repo: web::Data<UserRepository>, userinfo_url: web::Data<String>, code: web::Query<Code>) -> Result<impl Responder, Error> {
    match client
        .exchange_code(AuthorizationCode::new(code.code.clone()))
        .request_async(async_http_client).await {
        Ok(token_response) => {
            let id: User = User::new(get_user_info(&userinfo_url, token_response.access_token().secret()).await?.email)?;
            let user_entity:UserIdentity = UserIdentity::from(user_repo.into_inner().create(&id).await?);
            match Identity::login(&req.extensions(), serde_json::to_string(&user_entity)?) {
                Ok(_) => {
                    Ok(HttpResponse::Found().insert_header(("Location", "/")).finish())
                }
                Err(err) => {
                    Err(Error::AuthError(format!("failed to get oidc token {}", err.to_string())))
                }
            }
        }
        Err(err) => {
            Err(Error::AuthError(format!("failed to get oidc token {}", err.to_string())))
        }
    }
}

async fn new_token(user: UserIdentity, token_repo: web::Data<TokenRepository>) -> Result<impl Responder, Error> {
    let token = token_repo.into_inner().create(&Token::new(user.id)?).await?;
    Ok(HttpResponse::Ok().json(TokenDTO::from(token)))
}

async fn list_token(user: UserIdentity, token_repo: web::Data<TokenRepository>) -> Result<impl Responder, Error> {
    let token = token_repo.into_inner().get_token_by_user_id(user.id).await?;
    let mut results = vec![];
    for t in token.into_iter() {
        results.push(TokenDTO::from(t));
    }
    Ok(HttpResponse::Ok().json(results))
}

// NOTE: openidconnect can't handle the case when null is returned in the userinfo, we have to handle it this way.
// https://github.com/ramosbugs/openidconnect-rs/issues/100
async fn get_user_info(userinfo_url: &str, access_token: &str) -> Result<UserEmail, Error> {
    let mut auth_header = header::HeaderMap::new();
    auth_header.insert("Authorization", header::HeaderValue::from_str( access_token)?);
    match Client::builder().default_headers(auth_header).build() {
        Ok(client) => {
            let resp: UserEmail = client.get(userinfo_url).send().await?.json().await?;
            Ok(resp)
        }
        Err(err) => {
            Err(Error::AuthError(err.to_string()))
        }
    }
}



pub fn get_scope() -> Scope {
    web::scope("/users")
        .service(web::resource("/").route(web::get().to(info)))
        .service(web::resource("/login").route(web::get().to(login)))
        .service(web::resource("/logout").route(web::post().to(logout)))
        .service(web::resource("/callback").route(web::get().to(callback)))
        .service(web::resource("/api_keys").route(web::get().to(new_token)).route(web::post().to(list_token)))
}