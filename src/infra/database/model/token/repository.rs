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

use crate::domain::token::entity::{Token};
use crate::domain::token::repository::Repository;
use crate::util::error::Result;
use async_trait::async_trait;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, ActiveValue::Set, Condition, ActiveModelTrait};
use crate::infra::database::model::token;
use crate::infra::database::model::token::dto::Entity as TokenDTO;
use crate::util::error;
use crate::util::key::get_token_hash;


#[derive(Clone)]
pub struct TokenRepository {
    db_connection: DatabaseConnection
}

impl TokenRepository {
    pub fn new(db_connection: DatabaseConnection) -> Self {
        Self {
            db_connection,
        }
    }
}

#[async_trait]
impl Repository for TokenRepository {
    async fn create(&self, token: Token) -> Result<Token> {
        let token = token::dto::ActiveModel {
            user_id: Set(token.user_id),
            description: Set(token.description),
            token: Set(get_token_hash(&token.token)),
            create_at:Set(token.create_at),
            expire_at: Set(token.expire_at),
            ..Default::default()
        };
        Ok(Token::from(token.insert(&self.db_connection).await?))
    }

    async fn get_token_by_id(&self, id: i32) -> Result<Token> {
        match TokenDTO::find_by_id(id).one(&self.db_connection).await? {
            None => {
                Err(error::Error::NotFoundError)
            }
            Some(token) => {
                Ok(Token::from(token))
            }
        }
    }

    async fn get_token_by_value(&self, token: &str) -> Result<Token> {
        match TokenDTO::find().filter(
            token::dto::Column::Token.eq(get_token_hash(token))).one(
            &self.db_connection).await? {
            None => {
                Err(error::Error::NotFoundError)
            }
            Some(token) => {
                Ok(Token::from(token))
            }
        }


    }

    async fn delete_by_user_and_id(&self, id: i32, user_id: i32) -> Result<()> {
        let _ = TokenDTO::delete_many().filter(Condition::all()
            .add(token::dto::Column::Id.eq(id))
            .add(token::dto::Column::UserId.eq(user_id))).exec(&self.db_connection)
            .await?;
        Ok(())
    }

    async fn get_token_by_user_id(&self, id: i32) -> Result<Vec<Token>> {
        let tokens = TokenDTO::find().filter(
            token::dto::Column::UserId.eq(id)).all(&self.db_connection).await?;
        let mut results = vec![];
        for dto in tokens.into_iter() {
            results.push(Token::from(dto));
        }
        Ok(results)
    }
}