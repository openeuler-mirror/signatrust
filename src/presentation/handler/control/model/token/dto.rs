



use serde::{Deserialize, Serialize};
use std::convert::From;
use chrono::{DateTime, Utc};
use crate::domain::token::entity::Token;


#[derive(Debug, Deserialize, Serialize)]
pub struct TokenDTO {
    pub token: String,
    pub expire_at: DateTime<Utc>
}


impl From<TokenDTO> for Token {
    fn from(token: TokenDTO) -> Self {
        Token {
            id: 0,
            user_id: 0,
            token: token.token.clone(),
            expire_at: token.expire_at,
        }
    }
}

impl From<Token> for TokenDTO {
    fn from(token: Token) -> Self {
        TokenDTO {
            token: token.token.clone(),
            expire_at: token.expire_at,
        }
    }
}