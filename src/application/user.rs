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

use crate::domain::user::entity::User;
use crate::domain::token::entity::Token;
use crate::domain::user::repository::Repository as UserRepository;
use crate::domain::token::repository::Repository as TokenRepository;
use crate::util::error::{Result, Error};
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::RwLock;
use serde::{Deserialize};
use config::Config;
use reqwest::{header, Client};
use crate::presentation::handler::control::model::user::dto::UserIdentity;
use openidconnect::{
    Scope,
    AuthenticationFlow, CsrfToken, Nonce,
    core::CoreResponseType, core::CoreClient
};
use openidconnect::{JsonWebKeySet, ClientId, AuthUrl, UserInfoUrl, TokenUrl, RedirectUrl, ClientSecret, IssuerUrl};
use url::Url;

#[async_trait]
pub trait UserService: Send + Sync{
    async fn get_token(&self, u: &UserIdentity) -> Result<Vec<Token>>;
    async fn get_token_by_value(&self, token: &str) -> Result<Token>;
    async fn save(&self, u: &User) -> Result<User>;
    async fn get_user_by_id(&self, id: i32) -> Result<User>;
    async fn get_by_email(&self, email: &str) -> Result<User>;
    async fn generate_token(&self, u: &UserIdentity) -> Result<Token>;
    async fn get_login_url(&self) -> Result<Url>;
    async fn validate_user(&self, code: &str) -> Result<User>;
}

#[derive(Deserialize, Debug)]
pub struct UserEmail {
    pub email: String,
}

#[derive(Deserialize, Debug)]
pub struct AccessToken {
    pub access_token: String,
}

pub struct OIDCConfig {
    pub client_id: String,
    pub client_secret: String,
    pub token_url: String,
    pub redirect_uri: String,
    pub user_info_url: String,
    pub auth_url: String
}


pub struct DBUserService<R, T>
where
    R: UserRepository,
    T: TokenRepository
{
    user_repository: R,
    token_repository: T,
    oidc_config: OIDCConfig,
    client: CoreClient
}

impl<R, T> DBUserService<R, T>
    where
        R: UserRepository,
        T: TokenRepository
{
    pub fn new(user_repository: R, token_repository: T, config: Arc<RwLock<Config>>) -> Result<Self> {
        // TODO: remove me when openid connect library is ready we have to save OIDC in another object
        // due to we hacked several OIDC methods.
        let oidc_config = OIDCConfig{
            auth_url: config.read()?.get_string("oidc.auth_url")?,
            client_id: config.read()?.get_string("oidc.client_id")?,
            client_secret: config.read()?.get_string("oidc.client_secret")?,
            token_url: config.read()?.get_string("oidc.token_url")?,
            redirect_uri: config.read()?.get_string("oidc.redirect_url")?,
            user_info_url: config.read()?.get_string("oidc.userinfo_url")?,
        };
        let client = CoreClient::new(
            ClientId::new(oidc_config.client_id.clone()),
            Some(ClientSecret::new(oidc_config.client_secret.clone())),
            IssuerUrl::new(oidc_config.auth_url.clone())?,
            AuthUrl::new(oidc_config.auth_url.clone())?,
            Some(TokenUrl::new(oidc_config.token_url.clone())?),
            Some(UserInfoUrl::new(oidc_config.user_info_url.clone())?),
            JsonWebKeySet::default()).set_redirect_uri(RedirectUrl::new(oidc_config.redirect_uri.clone())?,
        );
        Ok(Self {
            user_repository,
            token_repository,
            oidc_config,
            client
        })
    }

    // NOTE: openidconnect can't handle the case when null is returned in the userinfo, we have to handle it this way.
    // https://github.com/ramosbugs/openidconnect-rs/issues/100
    async fn get_user_info(&self, access_token: &str) -> Result<UserEmail> {
        let mut auth_header = header::HeaderMap::new();
        auth_header.insert("Authorization", header::HeaderValue::from_str( access_token)?);
        match Client::builder().default_headers(auth_header).build() {
            Ok(client) => {
                let resp: UserEmail = client.get(&self.oidc_config.user_info_url).send().await?.json().await?;
                Ok(resp)
            }
            Err(err) => {
                Err(Error::AuthError(err.to_string()))
            }
        }
    }

    // NOTE: openidconnect can't handle the case additional attributes returned in the token API
    async fn get_access_token(&self, code: &str) -> Result<AccessToken> {
        match Client::builder().build() {
            Ok(client) => {
                let token: AccessToken = client.post(&self.oidc_config.token_url).query(&[
                    ("client_id", self.oidc_config.client_id.as_str()),
                    ("client_secret", self.oidc_config.client_secret.as_str()),
                    ("code", code),
                    ("redirect_uri", self.oidc_config.redirect_uri.as_str()),
                    ("grant_type", "authorization_code")]).send().await?.json().await?;
                Ok(token)
            }
            Err(err) => {
                Err(Error::AuthError(err.to_string()))
            }
        }
    }
}

#[async_trait]
impl<R, T> UserService for DBUserService<R, T>
where
    R: UserRepository,
    T: TokenRepository
{
    async fn get_token_by_value(&self, token: &str) -> Result<Token> {
        self.token_repository.get_token_by_value(token).await
    }

    async fn save(&self, u: &User) -> Result<User> {
        return self.user_repository.create(u).await
    }

    async fn get_token(&self, user: &UserIdentity) -> Result<Vec<Token>> {
        self.token_repository.get_token_by_user_id(user.id).await
    }

    async fn get_by_email(&self, email: &str) -> Result<User> {
        self.user_repository.get_by_email(email).await
    }

    async fn generate_token(&self, u: &UserIdentity) -> Result<Token> {
        return self.token_repository.create(&Token::new(u.id)?).await
    }

    async fn get_login_url(&self) -> Result<Url> {
        let (authorize_url, _, _) = self.client
            .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                           CsrfToken::new_random, Nonce::new_random, )
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url();
        Ok(authorize_url)
    }

    async fn validate_user(&self, code: &str) -> Result<User> {
        match self.get_access_token(&code).await {
            Ok(token_response) => {
                let id: User = User::new(self.get_user_info(&token_response.access_token).await?.email)?;
                return self.user_repository.create(&id).await
            }
            Err(err) => {
                Err(Error::AuthError(format!("failed to get access token {}", err)))
            }
        }
    }

    async fn get_user_by_id(&self, id: i32) -> Result<User> {
        self.user_repository.get_by_id(id).await
    }
}
