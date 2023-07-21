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
use sqlx::FromRow;
use chrono::{DateTime, Utc};

use crate::domain::token::entity::Token;
use crate::util::key::get_token_hash;

#[derive(Debug, FromRow, Clone)]
pub(super) struct TokenDTO {
    pub id: i32,
    pub user_id: i32,
    pub description: String,
    pub token: String,
    pub create_at: DateTime<Utc>,
    pub expire_at: DateTime<Utc>,
}

impl From<Token> for TokenDTO {
    fn from(token: Token) -> Self {
        Self {
            id: token.id,
            user_id: token.user_id,
            description: token.description.clone(),
            token: get_token_hash(&token.token),
            create_at: token.create_at,
            expire_at: token.expire_at,
        }
    }
}

impl From<TokenDTO> for Token {
    fn from(dto: TokenDTO) -> Self {
        Self {
            id: dto.id,
            user_id: dto.user_id,
            description: dto.description.clone(),
            token: dto.token.clone(),
            create_at: dto.create_at,
            expire_at:dto.expire_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_token_dto_from_entity() {
        let token = Token::new(1, "Test token".to_string(), "abc123".to_string()).unwrap();
        let token_hash = get_token_hash(&token.token);
        let dto = TokenDTO::from(token.clone());
        assert_eq!(dto.id, token.id);
        assert_eq!(dto.user_id, token.user_id);
        assert_eq!(dto.description, token.description);
        assert_ne!(dto.token, token.token);
        assert_eq!(dto.token, token_hash);
        assert_eq!(dto.create_at, token.create_at);
        assert_eq!(dto.expire_at, token.expire_at);
    }

    #[test]
    fn test_token_entity_from_dto() {
        let now = Utc::now();
        let dto = TokenDTO {
            id: 1,
            user_id: 2,
            description: "Test token".to_string(),
            token: "hashedtoken".to_string(),
            create_at: now,
            expire_at: now + chrono::Duration::days(1)
        };
        let token = Token::from(dto.clone());
        assert_eq!(token.id, dto.id);
        assert_eq!(token.user_id, dto.user_id);
        assert_eq!(token.description, dto.description);
        assert_eq!(token.token, dto.token);
        assert_eq!(token.create_at, dto.create_at);
        assert_eq!(token.expire_at, dto.expire_at);
    }
}

