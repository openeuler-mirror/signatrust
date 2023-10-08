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

use config::Value;
use once_cell::sync::OnceCell;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use sqlx::mysql::MySql;
use sqlx::pool::Pool;
use std::collections::HashMap;
use std::time::Duration;

use crate::util::error::{Error, Result};
pub type DbPool = Pool<MySql>;

//Now we have database pool for sqlx framework and database connection for sea-orm framework,
static DB_CONNECTION: OnceCell<DatabaseConnection> = OnceCell::new();

pub async fn create_pool(config: &HashMap<String, Value>) -> Result<()> {
    let max_connections: u32 = config
        .get("max_connection")
        .expect("max connection should configured")
        .to_string()
        .parse()?;
    if max_connections == 0 {
        return Err(Error::ConfigError(format!(
            "max connection for database is incorrect {}",
            max_connections
        )));
    }
    let db_connection = config
        .get("connection_url")
        .expect("database connection url should configured")
        .to_string();
    if db_connection.is_empty() {
        return Err(Error::ConfigError(format!(
            "database connection url is incorrect {}",
            db_connection
        )));
    }
    //initialize the database connection
    let mut opt = ConnectOptions::new(db_connection);
    opt.max_connections(max_connections)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(8))
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .sqlx_logging(true)
        .sqlx_logging_level(log::LevelFilter::Info);

    DB_CONNECTION
        .set(Database::connect(opt).await?)
        .expect("database connection configured");
    get_db_connection()?
        .ping()
        .await
        .expect("database connection failed");
    Ok(())
}
pub fn get_db_connection() -> Result<&'static DatabaseConnection> {
    return match DB_CONNECTION.get() {
        None => Err(Error::DatabaseError(
            "failed to get database pool".to_string(),
        )),
        Some(pool) => Ok(pool),
    };
}

#[cfg(test)]
mod tests {
    use crate::util::error::Result;
    use testcontainers::clients;
    use testcontainers::core::WaitFor;
    use testcontainers::images::generic::GenericImage;

    #[tokio::test]
    async fn test_database_migration() -> Result<()> {
        let docker = clients::Cli::default();
        let image = GenericImage::new("mysql", "8.0")
            .with_env_var("MYSQL_DATABASE", "signatrust")
            .with_env_var("MYSQL_PASSWORD", "test")
            .with_env_var("MYSQL_USER", "test")
            .with_env_var("MYSQL_ROOT_PASSWORD", "root")
            .with_wait_for(WaitFor::message_on_stderr("ready for connections"));
        let database = docker.run(image.clone());

        let sqlx_image = GenericImage::new("tommylike/sqlx-cli", "0.7.1.1")
            .with_env_var(
                "DATABASE_HOST",
                database.get_bridge_ip_address().to_string(),
            )
            .with_env_var("DATABASE_PORT", "3306")
            .with_env_var("DATABASE_USER", "test")
            .with_env_var("DATABASE_PASSWORD", "test")
            .with_env_var("DATABASE_NAME", "signatrust")
            .with_volume("./migrations/", "/app/migrations/")
            .with_entrypoint("/app/run_migrations.sh")
            .with_wait_for(WaitFor::message_on_stdout(
                "Applied 20230727020628/migrate extend-datakey-name",
            ));
        let _migration = docker.run(sqlx_image.clone());
        Ok(())
    }
}
