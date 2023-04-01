



use serde::{Deserialize, Serialize};
use std::convert::From;
use chrono::{DateTime, Utc};
use crate::domain::token::entity::Token;


#[derive(Debug, Deserialize, Serialize)]
pub struct TokenDTO {
    #[serde(skip_deserializing)]
    pub id: i32,
    #[serde(skip_deserializing)]
    pub user_id: i32,
    #[serde(skip_deserializing)]
    pub token: String,
    pub description: String,
    #[serde(skip_deserializing)]
    pub create_at: DateTime<Utc>,
    #[serde(skip_deserializing)]
    pub expire_at: DateTime<Utc>
}

impl TokenDTO {
    pub fn new(description: String) -> TokenDTO {
        TokenDTO {
            id: 0,
            user_id: 0,
            //disable parse hash to dto
            token: "".to_string(),
            description,
            expire_at: Default::default(),
            create_at: Default::default(),
        }
    }
}


impl From<TokenDTO> for Token {
    fn from(token: TokenDTO) -> Self {
        Token {
            id: 0,
            user_id: 0,
            description: token.description.clone(),
            token: Default::default(),
            create_at: Default::default(),
            expire_at: Default::default(),
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
            expire_at: token.expire_at,
            create_at: token.create_at,
        }
    }
}