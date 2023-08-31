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

use super::dto::Entity as UserDTO;
use crate::infra::database::model::user;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, ActiveValue::Set, ActiveModelTrait};
use crate::domain::user::entity::User;
use crate::domain::user::repository::Repository;
use crate::util::error::{Error, Result};
use async_trait::async_trait;

#[derive(Clone)]
pub struct UserRepository<'a> {
    db_connection: &'a DatabaseConnection
}

impl<'a> UserRepository<'a> {
    pub fn new(db_connection: &'a DatabaseConnection) -> Self {
        Self {
            db_connection,
        }
    }
}

#[async_trait]
impl<'a> Repository for UserRepository<'a> {

    async fn create(&self, user: User) -> Result<User> {
        return match self.get_by_email(&user.email).await {
            Ok(existed) => {
                Ok(existed)
            }
            Err(_err) => {
                let user = user::dto::ActiveModel {
                    email: Set(user.email),
                    ..Default::default()
                };
                Ok(User::from(user.insert(self.db_connection).await?))
            }
        }
    }

    async fn get_by_id(&self, id: i32) -> Result<User> {
        match UserDTO::find_by_id(id).one(
            self.db_connection).await? {
            None => {
                Err(Error::NotFoundError)
            }
            Some(user) => {
                Ok(User::from(user))
            }
        }
    }

    async fn get_by_email(&self, email: &str) -> Result<User> {
        match UserDTO::find().filter(
            user::dto::Column::Email.eq(email)).one(
            self.db_connection).await? {
            None => {
                Err(Error::NotFoundError)
            }
            Some(user) => {
                Ok(User::from(user))
            }
        }
    }

    async fn delete_by_id(&self, id: i32) -> Result<()> {
        let _ = UserDTO::delete_by_id(id).exec(self.db_connection)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};
    use crate::domain::user::entity::User;
    use crate::domain::user::repository::Repository;
    use crate::infra::database::model::user::dto;
    use crate::util::error::Result;
    use crate::infra::database::model::user::repository::UserRepository;

    #[tokio::test]
    async fn test_user_repository_query_sql_statement() -> Result<()> {
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([
                vec![dto::Model {
                    id: 1,
                    email: "fake_email".to_string(),
                }],
                vec![dto::Model {
                    id: 2,
                    email: "fake_email".to_string(),
                }],
            ]).into_connection();

        let user_repository = UserRepository::new(&db);
        assert_eq!(
            user_repository.get_by_email("fake_email").await?,
            User::from(dto::Model {
                id: 1,
                email: "fake_email".to_string(),
            })
        );

        assert_eq!(
            user_repository.get_by_id(1).await?,
            User::from(dto::Model {
                id: 2,
                email: "fake_email".to_string(),
            })
        );

        assert_eq!(
            db.into_transaction_log(),
            [
                //get_by_email
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `user`.`id`, `user`.`email` FROM `user` WHERE `user`.`email` = ? LIMIT ?"#,
                    ["fake_email".into(), 1u64.into()]
                ),
                //get_by_id
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `user`.`id`, `user`.`email` FROM `user` WHERE `user`.`id` = ? LIMIT ?"#,
                    [1i32.into(), 1u64.into()]
                ),
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_user_repository_create_sql_statement() -> Result<()> {
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([
                vec![],
                vec![dto::Model {
                    id: 3,
                    email: "fake_email".to_string(),
                }],
            ]).append_exec_results([
            MockExecResult{
                last_insert_id: 3,
                rows_affected: 1,
            }
        ]).into_connection();

        let user_repository = UserRepository::new(&db);
        let user = User{
            id: 0,
            email: "fake_string".to_string(),
        };
        assert_eq!(
            user_repository.create(user).await?,
            User::from(dto::Model {
                id: 3,
                email: "fake_email".to_string(),
            })
        );
        assert_eq!(
            db.into_transaction_log(),
            [
                //create
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `user`.`id`, `user`.`email` FROM `user` WHERE `user`.`email` = ? LIMIT ?"#,
                    ["fake_string".into(), 1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"INSERT INTO `user` (`email`) VALUES (?)"#,
                    ["fake_string".into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `user`.`id`, `user`.`email` FROM `user` WHERE `user`.`id` = ? LIMIT ?"#,
                    [3i32.into(), 1u64.into()]
                ),
            ]
        );

        Ok(())
    }
    #[tokio::test]
    async fn test_user_repository_delete_sql_statement() -> Result<()> {
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([
                vec![dto::Model {
                    id: 1,
                    email: "fake_email".to_string(),
                }],
            ]).append_exec_results([
            MockExecResult{
                last_insert_id: 1,
                rows_affected: 1,
            }
        ]).into_connection();

        let user_repository = UserRepository::new(&db);
        assert_eq!(user_repository.delete_by_id(1).await?, ());
        assert_eq!(
            db.into_transaction_log(),
            [
                //delete
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"DELETE FROM `user` WHERE `user`.`id` = ?"#,
                    [1i32.into()]
                ),
            ]
        );

        Ok(())
    }
}
