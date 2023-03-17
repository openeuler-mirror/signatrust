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
use std::sync::{Arc, RwLock};


use actix_web::{App, HttpServer, middleware, web, cookie::Key};
use config::Config;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};




use actix_identity::IdentityMiddleware;
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use time::Duration as timeDuration;


use crate::infra::cipher::engine::{EncryptionEngine, EncryptionEngineWithClusterKey};
use crate::infra::database::model::clusterkey::repository;
use crate::infra::database::model::datakey::repository as datakeyRepository;
use crate::infra::database::pool::{create_pool, get_db_pool};
use crate::infra::kms::factory;





use crate::service::control_service::*;

use crate::util::error::Result;
use openidconnect::core::{
    CoreClient,
};
use openidconnect::{JsonWebKeySet, ClientId, AuthUrl, UserInfoUrl, TokenUrl, RedirectUrl, ClientSecret, IssuerUrl};
use crate::infra::database::model::token::repository::TokenRepository;
use crate::infra::database::model::user::repository::UserRepository;

pub struct ControlServer {
    server_config: Arc<RwLock<Config>>,
    data_key_repository: web::Data<datakeyRepository::EncryptedDataKeyRepository>,
    user_repository: web::Data<UserRepository>,
    token_repository: web::Data<TokenRepository>,
}

impl ControlServer {
    pub async fn new(server_config: Arc<RwLock<Config>>) -> Result<Self> {
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
        //initialize user repo
        let user_repo = UserRepository::new(get_db_pool()?);
        //initialize user repo
        let token_repo = TokenRepository::new(get_db_pool()?);
        let server = ControlServer {
            server_config,
            data_key_repository: web::Data::new(data_repository),
            user_repository: web::Data::new(user_repo),
            token_repository: web::Data::new(token_repo),
        };
        Ok(server)
    }

    pub fn initialize_oidc_client(&self) -> Result<CoreClient> {
        Ok(CoreClient::new(
            ClientId::new(self.server_config.read()?.get_string("oidc.client_id")?),
            Some(ClientSecret::new(self.server_config.read()?.get_string("oidc.client_secret")?)),
            IssuerUrl::new(self.server_config.read()?.get_string("oidc.auth_url")?)?,
            AuthUrl::new(self.server_config.read()?.get_string("oidc.auth_url")?)?,
            Some(TokenUrl::new(self.server_config.read()?.get_string("oidc.token_url")?)?),
            Some(UserInfoUrl::new(self.server_config.read()?.get_string("oidc.userinfo_url")?)?),
            JsonWebKeySet::default()).set_redirect_uri(RedirectUrl::new(self.server_config.read()?.get_string("oidc.redirect_url")?)?,
        ))
    }

    pub async fn run(&self) -> Result<()> {
        //start actix web server
        let addr: SocketAddr = format!(
            "{}:{}",
            self.server_config
                .read()?
                .get_string("control-server.server_ip")?,
            self.server_config
                .read()?
                .get_string("control-server.server_port")?
        )
            .parse()?;

        let key = self.server_config.read()?.get_string("control-server.cookie_key")?;

        //initialize oidc client
        let client = web::Data::new(self.initialize_oidc_client()?);
        //TODO: remove me when openid connect library is ready
        let user_info_url = web::Data::new(self.server_config.read()?.get_string("oidc.userinfo_url")?);

        info!("control server starts");
        // Start http server
        let data_key_repository = self.data_key_repository.clone();
        let user_repository = self.user_repository.clone();
        let token_repository = self.token_repository.clone();
        let http_server = HttpServer::new(move || {
            App::new()
                // enable logger
                .app_data(data_key_repository.clone())
                .app_data(client.clone())
                .app_data(user_info_url.clone())
                .app_data(user_repository.clone())
                .app_data(token_repository.clone())
                .wrap(middleware::Logger::default())
                .wrap(IdentityMiddleware::default())
                .wrap(
                    SessionMiddleware::builder(
                        CookieSessionStore::default(), Key::from(key.as_bytes()))
                        .session_lifecycle(PersistentSession::default().session_ttl(timeDuration::hours(1)))
                        .cookie_name("signatrust".to_owned())
                        .cookie_secure(false)
                        .cookie_domain(None)
                        .cookie_path("/".to_owned())
                        .build(),
                )
                .service(web::scope("/api/v1")
                    .service(user_service::get_scope())
                    .service(datakey_service::get_scope()))
        });
        if self.server_config
            .read()?
            .get_string("tls_cert")?
            .is_empty()
            || self
            .server_config
            .read()?
            .get_string("tls_key")?
            .is_empty() {
            info!("tls key and cert not configured, control server tls will be disabled");
            http_server.bind(addr)?.run().await?;
        } else {
            let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            builder
                .set_private_key_file(
                    self.server_config.read()?.get_string("tls_key")?, SslFiletype::PEM).unwrap();
            builder.set_certificate_chain_file(
                self.server_config.read()?.get_string("tls_cert")?).unwrap();
            http_server.bind_openssl(addr, builder)?.run().await?;
        }
        Ok(())
    }
}
