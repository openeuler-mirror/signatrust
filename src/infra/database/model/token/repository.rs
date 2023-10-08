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

use crate::domain::token::entity::Token;
use crate::domain::token::repository::Repository;
use crate::infra::database::model::token;
use crate::infra::database::model::token::dto::Entity as TokenDTO;
use crate::util::error;
use crate::util::error::Result;
use crate::util::key::get_token_hash;
use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, DatabaseConnection, EntityTrait,
    QueryFilter,
};

#[derive(Clone)]
pub struct TokenRepository<'a> {
    db_connection: &'a DatabaseConnection,
}

impl<'a> TokenRepository<'a> {
    pub fn new(db_connection: &'a DatabaseConnection) -> Self {
        Self { db_connection }
    }
}

#[async_trait]
impl<'a> Repository for TokenRepository<'a> {
    async fn create(&self, token: Token) -> Result<Token> {
        let token = token::dto::ActiveModel {
            user_id: Set(token.user_id),
            description: Set(token.description),
            token: Set(get_token_hash(&token.token)),
            create_at: Set(token.create_at),
            expire_at: Set(token.expire_at),
            ..Default::default()
        };
        Ok(Token::from(token.insert(self.db_connection).await?))
    }

    async fn get_token_by_id(&self, id: i32) -> Result<Token> {
        match TokenDTO::find_by_id(id).one(self.db_connection).await? {
            None => Err(error::Error::NotFoundError),
            Some(token) => Ok(Token::from(token)),
        }
    }

    async fn get_token_by_value(&self, token: &str) -> Result<Token> {
        match TokenDTO::find()
            .filter(token::dto::Column::Token.eq(get_token_hash(token)))
            .one(self.db_connection)
            .await?
        {
            None => Err(error::Error::NotFoundError),
            Some(token) => Ok(Token::from(token)),
        }
    }

    async fn delete_by_user_and_id(&self, id: i32, user_id: i32) -> Result<()> {
        let _ = TokenDTO::delete_many()
            .filter(
                Condition::all()
                    .add(token::dto::Column::Id.eq(id))
                    .add(token::dto::Column::UserId.eq(user_id)),
            )
            .exec(self.db_connection)
            .await?;
        Ok(())
    }

    async fn get_token_by_user_id(&self, id: i32) -> Result<Vec<Token>> {
        let tokens = TokenDTO::find()
            .filter(token::dto::Column::UserId.eq(id))
            .all(self.db_connection)
            .await?;
        let mut results = vec![];
        for dto in tokens.into_iter() {
            results.push(Token::from(dto));
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::token::entity::Token;
    use crate::domain::token::repository::Repository;
    use crate::infra::database::model::token::dto;
    use crate::infra::database::model::token::repository::TokenRepository;
    use crate::util::error::Result;
    use crate::util::key::get_token_hash;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    #[tokio::test]
    async fn test_token_repository_create_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([vec![dto::Model {
                id: 1,
                user_id: 0,
                description: "fake_token".to_string(),
                token: "random_number".to_string(),
                create_at: now.clone(),
                expire_at: now.clone(),
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection();

        let token_repository = TokenRepository::new(&db);
        let user = Token {
            id: 1,
            user_id: 0,
            description: "fake_token".to_string(),
            token: "random_number".to_string(),
            create_at: now.clone(),
            expire_at: now.clone(),
        };
        assert_eq!(
            token_repository.create(user).await?,
            Token::from(dto::Model {
                id: 1,
                user_id: 0,
                description: "fake_token".to_string(),
                token: "random_number".to_string(),
                create_at: now.clone(),
                expire_at: now.clone(),
            })
        );
        let hashed_token = get_token_hash("random_number");
        assert_eq!(
            db.into_transaction_log(),
            [
                //create
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"INSERT INTO `token` (`user_id`, `description`, `token`, `create_at`, `expire_at`) VALUES (?, ?, ?, ?, ?)"#,
                    [
                        0i32.into(),
                        "fake_token".into(),
                        hashed_token.into(),
                        now.clone().into(),
                        now.clone().into()
                    ]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `token`.`id`, `token`.`user_id`, `token`.`description`, `token`.`token`, `token`.`create_at`, `token`.`expire_at` FROM `token` WHERE `token`.`id` = ? LIMIT ?"#,
                    [1i32.into(), 1u64.into()]
                ),
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_token_repository_delete_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([vec![dto::Model {
                id: 1,
                user_id: 0,
                description: "fake_token".to_string(),
                token: "random_number".to_string(),
                create_at: now.clone(),
                expire_at: now.clone(),
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection();

        let token_repository = TokenRepository::new(&db);
        assert_eq!(token_repository.delete_by_user_and_id(1, 1).await?, ());
        assert_eq!(
            db.into_transaction_log(),
            [
                //delete
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"DELETE FROM `token` WHERE `token`.`id` = ? AND `token`.`user_id` = ?"#,
                    [1i32.into(), 1i32.into()]
                ),
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_token_repository_query_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([
                vec![dto::Model {
                    id: 1,
                    user_id: 0,
                    description: "fake_token".to_string(),
                    token: "random_number".to_string(),
                    create_at: now.clone(),
                    expire_at: now.clone(),
                }],
                vec![dto::Model {
                    id: 2,
                    user_id: 0,
                    description: "fake_token2".to_string(),
                    token: "random_number2".to_string(),
                    create_at: now.clone(),
                    expire_at: now.clone(),
                }],
                vec![
                    dto::Model {
                        id: 1,
                        user_id: 0,
                        description: "fake_token".to_string(),
                        token: "random_number".to_string(),
                        create_at: now.clone(),
                        expire_at: now.clone(),
                    },
                    dto::Model {
                        id: 2,
                        user_id: 0,
                        description: "fake_token2".to_string(),
                        token: "random_number2".to_string(),
                        create_at: now.clone(),
                        expire_at: now.clone(),
                    },
                ],
            ])
            .into_connection();

        let token_repository = TokenRepository::new(&db);
        assert_eq!(
            token_repository.get_token_by_id(1).await?,
            Token::from(dto::Model {
                id: 1,
                user_id: 0,
                description: "fake_token".to_string(),
                token: "random_number".to_string(),
                create_at: now.clone(),
                expire_at: now.clone(),
            })
        );
        assert_eq!(
            token_repository.get_token_by_value("fake_content").await?,
            Token::from(dto::Model {
                id: 2,
                user_id: 0,
                description: "fake_token2".to_string(),
                token: "random_number2".to_string(),
                create_at: now.clone(),
                expire_at: now.clone(),
            })
        );

        assert_eq!(
            token_repository.get_token_by_user_id(0).await?,
            vec![
                Token::from(dto::Model {
                    id: 1,
                    user_id: 0,
                    description: "fake_token".to_string(),
                    token: "random_number".to_string(),
                    create_at: now.clone(),
                    expire_at: now.clone(),
                }),
                Token::from(dto::Model {
                    id: 2,
                    user_id: 0,
                    description: "fake_token2".to_string(),
                    token: "random_number2".to_string(),
                    create_at: now.clone(),
                    expire_at: now.clone(),
                })
            ]
        );

        let hashed_token = get_token_hash("fake_content");
        assert_eq!(
            db.into_transaction_log(),
            [
                //get_token_by_id
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `token`.`id`, `token`.`user_id`, `token`.`description`, `token`.`token`, `token`.`create_at`, `token`.`expire_at` FROM `token` WHERE `token`.`id` = ? LIMIT ?"#,
                    [1i32.into(), 1u64.into()]
                ),
                //get_token_by_value
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `token`.`id`, `token`.`user_id`, `token`.`description`, `token`.`token`, `token`.`create_at`, `token`.`expire_at` FROM `token` WHERE `token`.`token` = ? LIMIT ?"#,
                    [hashed_token.into(), 1u64.into()]
                ),
                //get_token_by_user_id
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `token`.`id`, `token`.`user_id`, `token`.`description`, `token`.`token`, `token`.`create_at`, `token`.`expire_at` FROM `token` WHERE `token`.`user_id` = ?"#,
                    [0i32.into()]
                ),
            ]
        );

        Ok(())
    }
}
