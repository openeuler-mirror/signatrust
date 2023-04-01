use actix_web::{Result, HttpRequest, FromRequest, dev::Payload};
use crate::util::error::{Error};

use actix_identity::Identity;
use actix_web::web;
use std::pin::Pin;
use futures::Future;
use serde::{Deserialize, Serialize};
use std::convert::From;
use crate::application::user::UserService;
use crate::domain::user::entity::User;

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
                        if let Some(user_service) = req.clone().app_data::<web::Data<dyn UserService>>() {
                            if let Ok(token) = user_service.get_ref().get_valid_token(value.to_str().unwrap()).await {
                                if let Ok(user) = user_service.get_ref().get_user_by_id(token.user_id).await {
                                    return Ok(UserIdentity::from(user));
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