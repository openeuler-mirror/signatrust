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
use chrono::{DateTime, Utc};

use crate::domain::token::entity::Token;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Deserialize, Serialize)]
#[sea_orm(table_name = "token")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub user_id: i32,
    pub description: String,
    pub token: String,
    pub create_at: DateTime<Utc>,
    pub expire_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for Token {
    fn from(dto: Model) -> Self {
        Self {
            id: dto.id,
            user_id: dto.user_id,
            description: dto.description.clone(),
            token: dto.token.clone(),
            create_at: dto.create_at,
            expire_at: dto.expire_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    #[test]
    fn test_token_entity_from_dto() {
        let now = Utc::now();
        let dto = Model {
            id: 1,
            user_id: 2,
            description: "Test token".to_string(),
            token: "hashedtoken".to_string(),
            create_at: now,
            expire_at: now + chrono::Duration::days(1),
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
