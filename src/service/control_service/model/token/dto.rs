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

use serde::{Deserialize, Serialize};
use std::convert::From;
use chrono::{DateTime, Utc};
use crate::model::token::entity::Token;


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