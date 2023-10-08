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

use super::dto::Entity as ClusterKeyDTO;
use crate::domain::clusterkey::entity::ClusterKey;
use crate::domain::clusterkey::repository::Repository;
use crate::infra::database::model::clusterkey;
use crate::util::error::{Error, Result};
use async_trait::async_trait;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
};

#[derive(Clone)]
pub struct ClusterKeyRepository<'a> {
    db_connection: &'a DatabaseConnection,
}

impl<'a> ClusterKeyRepository<'a> {
    pub fn new(db_connection: &'a DatabaseConnection) -> Self {
        Self { db_connection }
    }
}

#[async_trait]
impl<'a> Repository for ClusterKeyRepository<'a> {
    async fn create(&self, cluster_key: ClusterKey) -> Result<()> {
        let cluster_key = clusterkey::dto::ActiveModel {
            data: Set(cluster_key.data),
            algorithm: Set(cluster_key.algorithm),
            identity: Set(cluster_key.identity),
            create_at: Set(cluster_key.create_at),
            ..Default::default()
        };
        //TODO: https://github.com/SeaQL/sea-orm/issues/1790
        ClusterKeyDTO::insert(cluster_key)
            .on_conflict(
                OnConflict::new()
                    .update_column(clusterkey::dto::Column::Id)
                    .to_owned(),
            )
            .exec(self.db_connection)
            .await?;
        Ok(())
    }

    async fn get_latest(&self, algorithm: &str) -> Result<Option<ClusterKey>> {
        match ClusterKeyDTO::find()
            .filter(clusterkey::dto::Column::Algorithm.eq(algorithm))
            .order_by_desc(clusterkey::dto::Column::Id)
            .one(self.db_connection)
            .await?
        {
            None => Ok(None),
            Some(cluster_key) => Ok(Some(ClusterKey::from(cluster_key))),
        }
    }

    async fn get_by_id(&self, id: i32) -> Result<ClusterKey> {
        match ClusterKeyDTO::find_by_id(id)
            .one(self.db_connection)
            .await?
        {
            None => Err(Error::NotFoundError),
            Some(cluster_key) => Ok(ClusterKey::from(cluster_key)),
        }
    }
    async fn delete_by_id(&self, id: i32) -> Result<()> {
        let _ = ClusterKeyDTO::delete_by_id(id)
            .exec(self.db_connection)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::clusterkey::entity::ClusterKey;
    use crate::domain::clusterkey::repository::Repository;
    use crate::infra::database::model::clusterkey::dto;
    use crate::infra::database::model::clusterkey::repository::ClusterKeyRepository;
    use crate::util::error::Result;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult, Transaction};

    #[tokio::test]
    async fn test_cluster_key_repository_create_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([vec![dto::Model {
                id: 0,
                data: vec![],
                algorithm: "".to_string(),
                identity: "".to_string(),
                create_at: now.clone(),
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection();

        let key_repository = ClusterKeyRepository::new(&db);
        let key = ClusterKey {
            id: 0,
            data: vec![],
            algorithm: "fake_algorithm".to_string(),
            identity: "123".to_string(),
            create_at: now.clone(),
        };
        assert_eq!(key_repository.create(key).await?, ());
        assert_eq!(
            db.into_transaction_log(),
            [
                //create
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"INSERT INTO `cluster_key` (`data`, `algorithm`, `identity`, `create_at`) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE `id` = VALUES(`id`)"#,
                    [
                        vec![].into(),
                        "fake_algorithm".into(),
                        "123".into(),
                        now.clone().into()
                    ]
                ),
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_cluster_key_repository_delete_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([vec![dto::Model {
                id: 1,
                data: vec![],
                algorithm: "fake_algorithm".to_string(),
                identity: "123".to_string(),
                create_at: now.clone(),
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection();

        let key_repository = ClusterKeyRepository::new(&db);
        assert_eq!(key_repository.delete_by_id(1).await?, ());
        assert_eq!(
            db.into_transaction_log(),
            [
                //delete
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"DELETE FROM `cluster_key` WHERE `cluster_key`.`id` = ?"#,
                    [1i32.into()]
                ),
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_cluster_key_repository_query_sql_statement() -> Result<()> {
        let now = chrono::Utc::now();
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([
                vec![dto::Model {
                    id: 1,
                    data: vec![],
                    algorithm: "fake_algorithm".to_string(),
                    identity: "123".to_string(),
                    create_at: now.clone(),
                }],
                vec![dto::Model {
                    id: 2,
                    data: vec![],
                    algorithm: "fake_algorithm".to_string(),
                    identity: "123".to_string(),
                    create_at: now.clone(),
                }],
            ])
            .into_connection();

        let key_repository = ClusterKeyRepository::new(&db);
        assert_eq!(
            key_repository.get_latest("fake_algorithm").await?,
            Some(ClusterKey::from(dto::Model {
                id: 1,
                data: vec![],
                algorithm: "fake_algorithm".to_string(),
                identity: "123".to_string(),
                create_at: now.clone(),
            }))
        );
        assert_eq!(
            key_repository.get_by_id(123).await?,
            ClusterKey::from(dto::Model {
                id: 2,
                data: vec![],
                algorithm: "fake_algorithm".to_string(),
                identity: "123".to_string(),
                create_at: now.clone(),
            })
        );
        assert_eq!(
            db.into_transaction_log(),
            [
                //get_latest
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `cluster_key`.`id`, `cluster_key`.`data`, `cluster_key`.`algorithm`, `cluster_key`.`identity`, `cluster_key`.`create_at` FROM `cluster_key` WHERE `cluster_key`.`algorithm` = ? ORDER BY `cluster_key`.`id` DESC LIMIT ?"#,
                    ["fake_algorithm".into(), 1u64.into()]
                ),
                //get_by_id
                Transaction::from_sql_and_values(
                    DatabaseBackend::MySql,
                    r#"SELECT `cluster_key`.`id`, `cluster_key`.`data`, `cluster_key`.`algorithm`, `cluster_key`.`identity`, `cluster_key`.`create_at` FROM `cluster_key` WHERE `cluster_key`.`id` = ? LIMIT ?"#,
                    [123i32.into(), 1u64.into()]
                ),
            ]
        );

        Ok(())
    }
}
