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

use actix_web::{App, HttpServer, middleware, web, cookie::Key};
use config::Config;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

use actix_identity::IdentityMiddleware;
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use time::Duration as timeDuration;

use crate::infra::database::model::datakey::repository as datakeyRepository;
use crate::infra::database::pool::{create_pool, get_db_pool};

use crate::presentation::handler::control::*;

use crate::util::error::Result;

use crate::application::datakey::{DBKeyService, KeyService};
use crate::infra::database::model::token::repository::TokenRepository;
use crate::infra::database::model::user::repository::UserRepository;
use crate::infra::sign_backend::factory::SignBackendFactory;
use crate::application::user::{DBUserService, UserService};
use crate::domain::datakey::entity::DataKey;
use crate::domain::token::entity::Token;
use crate::domain::user::entity::User;
use crate::presentation::handler::control::model::user::dto::UserIdentity;

pub struct ControlServer {
    server_config: Arc<RwLock<Config>>,
    user_service: Arc<dyn UserService>,
    key_service: Arc<dyn KeyService>,

}

impl ControlServer {
    pub async fn new(server_config: Arc<RwLock<Config>>) -> Result<Self> {
        let database = server_config.read()?.get_table("database")?;
        create_pool(&database).await?;
        let data_repository = datakeyRepository::DataKeyRepository::new(
            get_db_pool()?,
        );
        let sign_backend = SignBackendFactory::new_engine(
            server_config.clone(), get_db_pool()?).await?;
        //initialize repos
        let user_repo = UserRepository::new(get_db_pool()?);
        let token_repo = TokenRepository::new(get_db_pool()?);

        //initialize the service
        let user_service = Arc::new(
            DBUserService::new(
                user_repo.clone(), token_repo,
                server_config.clone())?) as Arc<dyn UserService>;
        let key_service = Arc::new(
            DBKeyService::new(
                data_repository, sign_backend)) as Arc<dyn KeyService>;
        let server = ControlServer {
            user_service,
            key_service,
            server_config,
        };
        Ok(server)
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

        info!("control server starts");
        // Start http server
        let user_service = web::Data::from(
            self.user_service.clone());
        let key_service = web::Data::from(
            self.key_service.clone());

        let http_server = HttpServer::new(move || {
            App::new()
                // enable logger
                .app_data(key_service.clone())
                .app_data(user_service.clone())
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
                    .service(user_handler::get_scope())
                    .service(datakey_handler::get_scope()))
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

    //used for control admin cmd
    pub async fn create_user_token(&self, user: &User) -> Result<Token> {
        let user = self.user_service.save(user).await?;
        self.user_service.generate_token(&UserIdentity::from(user)).await
    }

    //used for control admin cmd
    pub async fn create_keys(&self, data: &mut DataKey) -> Result<DataKey> {
        let key = self.key_service.create(data).await?;
        self.key_service.enable(key.id).await?;
        Ok(key)
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<User> {
        self.user_service.get_by_email(email).await
    }
}
