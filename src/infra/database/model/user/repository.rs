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
pub struct UserRepository {
    db_connection: DatabaseConnection
}

impl UserRepository {
    pub fn new(db_connection: DatabaseConnection) -> Self {
        Self {
            db_connection,
        }
    }
}

#[async_trait]
impl Repository for UserRepository {

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
                Ok(User::from(user.insert(&self.db_connection).await?))
            }
        }
    }

    async fn get_by_id(&self, id: i32) -> Result<User> {
        match UserDTO::find_by_id(id).one(
            &self.db_connection).await? {
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
            &self.db_connection).await? {
            None => {
                Err(Error::NotFoundError)
            }
            Some(user) => {
                Ok(User::from(user))
            }
        }
    }

    async fn delete_by_id(&self, id: i32) -> Result<()> {
        let _ = UserDTO::delete_by_id(id).exec(&self.db_connection)
            .await?;
        Ok(())
    }
}
