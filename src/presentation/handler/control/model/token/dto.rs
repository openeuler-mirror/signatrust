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

use serde::{Deserialize, Serialize};
use std::convert::From;

use crate::domain::token::entity::Token;
use utoipa::ToSchema;

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
    pub expire_at: String,
}

impl CreateTokenDTO {
    pub fn new(description: String) -> CreateTokenDTO {
        CreateTokenDTO { description }
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
