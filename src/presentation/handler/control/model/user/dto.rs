use actix_web::{Result, HttpRequest, FromRequest, dev::Payload};
use crate::util::error::{Error};

use actix_identity::Identity;
use actix_web::web;
use std::pin::Pin;
use futures::Future;
use serde::{Deserialize, Serialize};
use std::convert::From;
use chrono::{Utc};
use crate::infra::database::model::token::repository::TokenRepository;
use crate::infra::database::model::user::repository::UserRepository;
use crate::domain::token::repository::Repository as tokenRepository;
use crate::domain::user::entity::User;
use crate::domain::user::repository::Repository as userRepository;

#[derive(Debug, Deserialize, Serialize)]
pub struct UserIdentity {
    pub email: String,
    pub id: i32,
}

impl FromRequest for UserIdentity {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<UserIdentity, Error>>>>;

    fn from_request(req: &HttpRequest, pl: &mut Payload) -> Self::Future {
        let mut login: Option<UserIdentity> = None;
        //fetch from session
        if let Ok(identity) = Identity::from_request(&req.clone(), pl).into_inner() {
            if let Ok(user_json) = identity.id() {
                if let Ok(user) = serde_json::from_str(&user_json) {
                    login = Some(user)
                }
            }
        }
        let req = req.clone();
        Box::pin(async move {
            match login {
                //fetch valid token
                None => {
                    if let Some(value) = req.clone().headers().get("Authorization") {
                        if let Some(tk_repo) = req.clone().app_data::<web::Data<TokenRepository>>() {
                            if let Ok(token) = tk_repo.get_ref().get_token_by_value(value.to_str().unwrap()).await {
                                //token exists and valid
                                if token.expire_at.gt(&Utc::now()) {
                                    if let Some(us_repo) = req.clone().app_data::<web::Data<UserRepository>>() {
                                        if let Ok(user) = us_repo.get_ref().get_by_id(token.user_id).await {
                                            return Ok(UserIdentity::from(user));
                                        }
                                    } else {
                                        warn!("unable to find token's user info");
                                    }
                                } else {
                                    warn!("token expired");
                                }
                            } else {
                                warn!("unable to find token record");
                            }
                        }
                    } else {
                        warn!("authorization header provided, while empty value");
                    }
                    Err(Error::UnauthorizedError)
                }
                Some(user) => {
                    Ok(user)
                }
            }
        })
    }
}

impl From<UserIdentity> for User {
    fn from(id: UserIdentity) -> Self {
        User {
            id: id.id,
            email: id.email
        }
    }
}

impl From<User> for UserIdentity {
    fn from(id: User) -> Self {
        UserIdentity {
            id: id.id,
            email: id.email,
        }
    }
}