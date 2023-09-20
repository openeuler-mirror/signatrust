use actix_web::{Result, HttpRequest, FromRequest, dev::Payload, dev::ServiceRequest, body::MessageBody,dev::ServiceResponse};
use crate::util::error::{Error, Result as SignatrustResult};
use std::convert::TryInto;
use actix_identity::Identity;
use actix_web_lab::middleware::Next;
use actix_web::web;
use std::pin::Pin;
use futures::Future;
use serde::{Deserialize, Serialize};
use std::convert::From;
use actix_web::http::header::HeaderName;
use crate::application::user::UserService;
use crate::domain::user::entity::User;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;
use csrf::{AesGcmCsrfProtection, CsrfProtection};
use data_encoding::BASE64;
use reqwest::header::HeaderValue;
use reqwest::StatusCode;
use secstr::SecVec;
use crate::util::error::Error::GeneratingKeyError;
use crate::util::key::generate_csrf_parent_token;

pub const CSRF_HEADER_NAME: &str = "Xsrf-Token";
pub const AUTH_HEADER_NAME: &str = "Authorization";
pub const SET_COOKIE_HEADER: &str = "set-cookie";


#[derive(Debug, Deserialize, Serialize, ToSchema, Clone)]
pub struct UserIdentity {
    pub email: String,
    pub id: i32,
    //these two only exist when calling from OIDC login
    pub csrf_generation_token: Option<Vec<u8>>,
    pub csrf_token: Option<String>
}

impl UserIdentity {
    pub fn from_user(id: User) -> Self {
        UserIdentity {
            id: id.id,
            email: id.email,
            csrf_token: None,
            csrf_generation_token: None
        }
    }

    pub fn from_user_with_csrf_token(id: User, protect_key: [u8; 32]) -> SignatrustResult<Self> {
        let protect = AesGcmCsrfProtection::from_key(protect_key);
        let random_token = generate_csrf_parent_token();
        let random_token_array = random_token.clone().try_into()?;
        //we don't use cookie here
        let token = protect.generate_token(&random_token_array)?;
        Ok(UserIdentity {
            id: id.id,
            email: id.email,
            csrf_generation_token: Some(random_token.to_vec()),
            csrf_token: Some(token.b64_string())
        })
    }

    pub fn generate_new_csrf_cookie(&self, protect_key: [u8; 32], ttl_seconds: i64) -> SignatrustResult<String> {
        if self.csrf_generation_token.is_none() || self.csrf_token.is_none() {
            return Err(GeneratingKeyError("csrf token is empty, cannot generate new csrf cookie".to_string()));
        }
        let protect = AesGcmCsrfProtection::from_key(protect_key);
        let generation_token: [u8; 64] = self.csrf_generation_token.clone().unwrap().try_into()?;
        let cookie = protect.generate_cookie(
            &generation_token, ttl_seconds)?;
        Ok(cookie.b64_string())
    }

    pub fn csrf_cookie_valid(&self, protect_key: [u8; 32], value: &str) -> SignatrustResult<bool> {
        let protect = AesGcmCsrfProtection::from_key(protect_key);
        Ok(protect.verify_token_pair(
            &protect.parse_token(
                &BASE64.decode(self.csrf_token.clone().unwrap().as_bytes())?)?,
            &protect.parse_cookie(
                &BASE64.decode(value.as_bytes())?)?))
    }

    pub async fn append_csrf_cookie(req: ServiceRequest,  next: Next<impl MessageBody + 'static>) -> core::result::Result<ServiceResponse<impl MessageBody + 'static>, actix_web::error::Error> {
        let mut response = next.call(req).await?;
        if let Ok(identity) = Identity::from_request(response.request(), &mut Payload::None).into_inner() {
             if let Ok(user_json) = identity.id() {
                 if let Ok(user) = serde_json::from_str::<UserIdentity>(&user_json) {
                     if response.status() == StatusCode::UNAUTHORIZED {
                         //only append csrf token in authorized response
                         return Ok(response);
                     }
                     //generate csrf cookie based on user token
                     if let Some(protect_key) = response.request().app_data::<web::Data<SecVec<u8>>>() {
                         if let Ok(protect_key_array) = protect_key.clone().unsecure().try_into() {
                             if let Ok(csrf_token) = user.generate_new_csrf_cookie(protect_key_array, 600) {
                                 let http_header = response.headers_mut();
                                 http_header.insert(
                                     HeaderName::from_static(SET_COOKIE_HEADER),
                                     HeaderValue::from_str(&format!("{}={}; Secure; Path=/; Max-Age=600", CSRF_HEADER_NAME, csrf_token)).unwrap(),
                                 );
                             } else {
                                 warn!("failed to generate csrf token in middleware");
                             }
                         }
                     }
                 }
             }
        }

        Ok(response)
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

impl FromRequest for UserIdentity {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<UserIdentity, Error>>>>;

    fn from_request(req: &HttpRequest, pl: &mut Payload) -> Self::Future {
        let mut login: Option<UserIdentity> = None;
        //fetch id from session
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
                // if API is invoked with API token,
                // we need to fetch user identity from database
                // and check whether the token is expired
                None => {
                    if let Some(value) = req.headers().get(AUTH_HEADER_NAME) {
                        if let Some(user_service) = req.app_data::<web::Data<dyn UserService>>() {
                            if let Ok(user) = user_service.get_ref().validate_token(value.to_str().unwrap()).await {
                                return Ok(UserIdentity::from_user(user));
                            } else {
                                warn!("unable to find token record");
                            }
                        }
                    } else {
                        warn!("authorization header provided, while empty value");
                    }
                    Err(Error::UnauthorizedError)
                }
                // or we have to check both the token and csrf value.
                Some(user) => {
                    if let Some(protect_key) = req.app_data::<web::Data<SecVec<u8>>>() {
                        if let Some(header) = req.headers().get(CSRF_HEADER_NAME) {
                            if let Ok(protect_key_array) = protect_key.clone().unsecure().try_into() {
                                if let Ok(true) = user.csrf_cookie_valid(protect_key_array, header.to_str().unwrap()) {
                                    return Ok(user)
                                } else {
                                    warn!("csrf header is invalid");
                                }
                            }
                        } else {
                            warn!("unable to find csrf cookie");
                        }
                    } else {
                        warn!("unable to find csrf protect key");
                    }
                    Err(Error::UnauthorizedError)
                }
            }
        })
    }
}

#[derive(Deserialize, IntoParams, Validate, ToSchema)]
pub struct Code {
    #[validate(length(min = 1))]
    pub code: String,
}

