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

use crate::infra::database::pool::DbPool;
use crate::domain::token::entity::{Token};
use crate::domain::token::repository::Repository;
use crate::util::error::Result;
use async_trait::async_trait;
use std::boxed::Box;

use crate::infra::database::model::token::dto::TokenDTO;
use crate::util::key::get_token_hash;


#[derive(Clone)]
pub struct TokenRepository {
    db_pool: DbPool,
}

impl TokenRepository {
    pub fn new(db_pool: DbPool) -> Self {
        Self {
            db_pool,
        }
    }
}

#[async_trait]
impl Repository for TokenRepository {

    async fn create(&self, token: Token) -> Result<Token> {
        let dto = TokenDTO::from(token);
        let record : u64 = sqlx::query("INSERT INTO token(user_id, description, token, create_at, expire_at) VALUES (?, ?, ?, ?, ?)")
            .bind(dto.user_id)
            .bind(&dto.description)
            .bind(&dto.token)
            .bind(dto.create_at)
            .bind(dto.expire_at)
            .execute(&self.db_pool)
            .await?.last_insert_id();
        self.get_token_by_id(record as i32).await
    }

    async fn get_token_by_id(&self, id: i32) -> Result<Token> {
        let selected: TokenDTO = sqlx::query_as("SELECT * FROM token WHERE id = ?")
            .bind(id)
            .fetch_one(&self.db_pool)
            .await?;
        Ok(Token::from(selected))
    }

    async fn get_token_by_value(&self, token: &str) -> Result<Token> {
        let selected: TokenDTO = sqlx::query_as("SELECT * FROM token WHERE token = ?")
            .bind(get_token_hash(token))
            .fetch_one(&self.db_pool)
            .await?;
        Ok(Token::from(selected))
    }

    async fn delete_by_user_and_id(&self, id: i32, user_id: i32) -> Result<()> {
        let _: Option<TokenDTO> = sqlx::query_as("DELETE FROM token where id = ? AND user_id = ?")
            .bind(id)
            .bind(user_id)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(())
    }

    async fn get_token_by_user_id(&self, id: i32) -> Result<Vec<Token>> {
        let dtos: Vec<TokenDTO> = sqlx::query_as("SELECT * FROM token WHERE user_id = ?")
            .bind(id)
            .fetch_all(&self.db_pool)
            .await?;
        let mut results = vec![];
        for dto in dtos.into_iter() {
            results.push(Token::from(dto));
        }
        Ok(results)
    }
}
