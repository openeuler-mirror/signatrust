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

#[derive(Debug, FromRow)]
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
