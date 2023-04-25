



use serde::{Deserialize, Serialize};
use std::convert::From;

use crate::domain::token::entity::Token;
use utoipa::{ToSchema};

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTokenDTO {
    pub description: String,
}


#[derive(Debug, Serialize, ToSchema)]
pub struct TokenDTO {
    #[serde(skip_deserializing)]
    pub id: i32,
    #[serde(skip_deserializing)]
    pub user_id: i32,
    #[serde(skip_deserializing)]
    pub token: String,
    pub description: String,
    #[serde(skip_deserializing)]
    pub create_at: String,
    #[serde(skip_deserializing)]
    pub expire_at: String
}

impl CreateTokenDTO {
    pub fn new(description: String) -> CreateTokenDTO {
        CreateTokenDTO {
            description,
        }
    }
}

impl From<Token> for TokenDTO {
    fn from(token: Token) -> Self {
        TokenDTO {
            id: token.id,
            user_id: token.user_id,
            token: token.token.clone(),
            description: token.description.clone(),
            expire_at: token.expire_at.to_string(),
            create_at: token.create_at.to_string(),
        }
    }
}