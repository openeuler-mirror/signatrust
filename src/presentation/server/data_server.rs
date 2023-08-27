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

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use config::{Config};
use tokio::fs;
use tokio_util::sync::CancellationToken;
use tonic::{
    transport::{
        Certificate,
        Identity, Server, ServerTlsConfig,
    },
};
use crate::application::datakey::{DBKeyService, KeyService};
use crate::application::user::{DBUserService, UserService};

use crate::infra::database::model::datakey::repository;
use crate::infra::database::model::token::repository::TokenRepository;
use crate::infra::database::model::user::repository::UserRepository;
use crate::infra::database::pool::{create_pool, get_db_connection, get_db_pool};
use crate::infra::sign_backend::factory::SignBackendFactory;


use crate::presentation::handler::data::sign_handler::get_grpc_handler as sign_grpc_handler;
use crate::presentation::handler::data::health_handler::get_grpc_handler as health_grpc_handler;
use crate::util::error::{Error, Result};
use crate::util::key::file_exists;

pub struct DataServer
{
    server_config: Arc<RwLock<Config>>,
    cancel_token: CancellationToken,
    server_identity: Option<Identity>,
    ca_cert: Option<Certificate>,
}

impl DataServer {
    pub async fn new(server_config: Arc<RwLock<Config>>, cancel_token: CancellationToken) -> Result<Self> {
        let database = server_config.read()?.get_table("database")?;
        create_pool(&database).await?;
        let mut server = DataServer {
            server_config,
            cancel_token,
            server_identity: None,
            ca_cert: None,
        };
        server.load().await?;
        Ok(server)
    }

    async fn load(&mut self) -> Result<()> {
        let ca_root = self.server_config.read()?.get("ca_root").unwrap_or(String::new()).to_string();
        let tls_cert = self.server_config.read()?.get("tls_cert").unwrap_or(String::new()).to_string();
        let tls_key = self.server_config.read()?.get("tls_key").unwrap_or(String::new()).to_string();
        if ca_root.is_empty() || tls_cert.is_empty() || tls_key.is_empty() {
            info!("tls key and cert not configured, data server tls will be disabled");
            return Ok(());
        }
        if !file_exists(&ca_root) || !file_exists(&tls_cert) || !file_exists(&tls_key) {
            return Err(Error::FileFoundError(format!("ca root: {} or tls cert: {} or key: {} file not found", ca_root, tls_key, tls_cert)));
        }
        self.ca_cert = Some(
            Certificate::from_pem(fs::read(ca_root).await?));
        self.server_identity = Some(Identity::from_pem(fs::read(tls_cert).await?,
                                                       fs::read(tls_key).await?));
        Ok(())
    }

    async fn shutdown_signal(&self) {
        loop {
            tokio::select! {
                _ = self.cancel_token.cancelled() => {
                    info!("cancel token received, will quit data server");
                     break;
                }
            }
        }
    }

    pub async fn run(&self) -> Result<()> {
        //start grpc server
        let addr: SocketAddr = format!(
            "{}:{}",
            self.server_config
                .read()?
                .get_string("data-server.server_ip")?,
            self.server_config
                .read()?
                .get_string("data-server.server_port")?
        )
        .parse()?;

        let mut server = Server::builder();
        info!("data server starts");
        let sign_backend = SignBackendFactory::new_engine(
            self.server_config.clone(), get_db_connection()?).await?;
        let data_repository = repository::DataKeyRepository::new(
            get_db_pool()?);
        let key_service = DBKeyService::new(data_repository, sign_backend);
        let user_repo = UserRepository::new(get_db_connection()?);
        let token_repo = TokenRepository::new(get_db_connection()?);
        let user_service = DBUserService::new(user_repo, token_repo, self.server_config.clone())?;

        key_service.start_cache_cleanup_loop(self.cancel_token.clone())?;
        user_service.start_cache_cleanup_loop(self.cancel_token.clone())?;
        if let Some(identity) = self.server_identity.clone() {
            server
                .tls_config(ServerTlsConfig::new().identity(identity).client_ca_root(self.ca_cert.clone().unwrap()))?
                .add_service(sign_grpc_handler(key_service, user_service))
                .add_service(health_grpc_handler())
                .serve_with_shutdown(addr, self.shutdown_signal())
                .await?
        } else {
            server
                .add_service(sign_grpc_handler(key_service, user_service))
                .add_service(health_grpc_handler())
                .serve_with_shutdown(addr, self.shutdown_signal())
                .await?
        }
        Ok(())
    }
}
