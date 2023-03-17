/*
 * // Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 * //
 * // signatrust is licensed under Mulan PSL v2.
 * // You can use this software according to the terms and conditions of the Mulan
 * // PSL v2.
 * // You may obtain a copy of Mulan PSL v2 at:
 * //         http://license.coscl.org.cn/MulanPSL2
 * // THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 * // KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * // NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * // See the Mulan PSL v2 for more details.
 */


use std::net::SocketAddr;
use std::sync::{Arc, atomic::AtomicBool, RwLock};
use std::sync::atomic::Ordering;

use config::Config;

use tokio::fs;
use tokio::time::{Duration, sleep};
use tonic::{
    transport::{
        Certificate,
        Identity, Server, ServerTlsConfig,
    },
};


use crate::infra::cipher::engine::{EncryptionEngine, EncryptionEngineWithClusterKey};
use crate::infra::database::model::clusterkey::repository;
use crate::infra::database::model::datakey::repository as datakeyRepository;
use crate::infra::database::pool::{create_pool, get_db_pool};
use crate::infra::kms::factory;





use crate::service::data_service::grpc_service::get_grpc_service;

use crate::util::error::Result;

pub struct DataServer {
    server_config: Arc<RwLock<Config>>,
    signal: Arc<AtomicBool>,
    server_identity: Option<Identity>,
    ca_cert: Option<Certificate>,
    data_key_repository: Arc<datakeyRepository::EncryptedDataKeyRepository>
}

impl DataServer {
    pub async fn new(server_config: Arc<RwLock<Config>>, signal: Arc<AtomicBool>) -> Result<Self> {
        //initialize database and kms backend
        let kms_provider = factory::KMSProviderFactory::new_provider(
            &server_config.read()?.get_table("kms-provider")?,
        )?;
        let database = server_config.read()?.get_table("database")?;
        create_pool(&database).await?;
        let repository =
            repository::EncryptedClusterKeyRepository::new(get_db_pool()?, kms_provider.clone());
        //initialize signature plugins
        let engine_config = server_config.read()?.get_table("encryption-engine")?;
        let mut engine = EncryptionEngineWithClusterKey::new(
            Arc::new(Box::new(repository.clone())),
            &engine_config,
        )?;
        engine.initialize().await?;
        let data_repository = datakeyRepository::EncryptedDataKeyRepository::new(
            get_db_pool()?,
            Arc::new(Box::new(engine)),
        );
        let mut server = DataServer {
            server_config,
            signal,
            server_identity: None,
            ca_cert: None,
            data_key_repository: Arc::new(data_repository)
        };
        server.load().await?;
        Ok(server)
    }

    async fn load(&mut self) -> Result<()> {
        if self
            .server_config
            .read()?
            .get_string("tls_cert")?
            .is_empty()
            || self
                .server_config
                .read()?
                .get_string("tls_key")?
                .is_empty()
        {
            info!("tls key and cert not configured, data server tls will be disabled");
            return Ok(());
        }
        self.ca_cert = Some(
            Certificate::from_pem(
                fs::read(self.server_config.read()?.get_string("ca_root")?).await?));
        self.server_identity = Some(Identity::from_pem(
            fs::read(self.server_config.read()?.get_string("tls_cert")?).await?,
            fs::read(self.server_config.read()?.get_string("tls_key")?).await?));
        Ok(())
    }

    async fn shutdown_signal(&self) {
        while !self.signal.load(Ordering::Relaxed) {
            sleep(Duration::from_secs(1)).await;
        }
        info!("quit signal received...")
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
        if let Some(identity) = self.server_identity.clone() {
            server
                .tls_config(ServerTlsConfig::new().identity(identity).client_ca_root(self.ca_cert.clone().unwrap()))?
                .add_service(get_grpc_service(self.data_key_repository.clone()))
                .serve_with_shutdown(addr, self.shutdown_signal())
                .await?
        } else {
            server
                .add_service(get_grpc_service(self.data_key_repository.clone()))
                .serve_with_shutdown(addr, self.shutdown_signal())
                .await?
        }
        Ok(())
    }
}
