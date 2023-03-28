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

#![allow(dead_code)]

use std::collections::HashMap;
use std::env;
use chrono::{Duration, Utc};
use crate::util::error::{Result};
use clap::{Parser, Subcommand};
use clap::{Args};
use crate::client::sign_identity;
use crate::client::cmd::traits::SignCommand;
use crate::domain::datakey::entity::{DataKey};
use crate::domain::user::entity::User;
use crate::presentation::handler::control::model::datakey::dto::DataKeyDTO;
use crate::presentation::handler::control::model::user::dto::UserIdentity;

mod util;
mod client;
mod infra;
mod domain;
mod application;
mod presentation;


#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

#[derive(Parser)]
#[command(name = "signatrust-admin")]
#[command(author = "TommyLike <tommylikehu@gmail.com>")]
#[command(version = "0.10")]
#[command(about = "Administrator command for signatrust server", long_about = None)]
pub struct App {
    #[arg(short, long)]
    #[arg(
    help = "path of configuration file, './client.toml' relative to working directory be used in default"
    )]
    config: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Create default admin and admin token", long_about = None)]
    CreateAdmin(CommandAdmin),
    #[command(about = "Generate keys for signing", long_about = None)]
    GenerateKeys(CommandGenerateKeys),
}

#[derive(Args)]
pub struct CommandAdmin {
    #[arg(long)]
    #[arg(help = "specify the email of admin")]
    email: String,
}

#[derive(Args)]
pub struct CommandGenerateKeys {
    #[arg(long)]
    #[arg(help = "specify the name of this key pairs")]
    name: String,
    #[arg(long)]
    #[arg(help = "specify the the description of this key pairs")]
    description: String,
    #[arg(long)]
    #[arg(help = "specify the type of internal key used for this key pairs, ie, rsa")]
    param_key_type: String,
    #[arg(long)]
    #[arg(help = "specify the type of internal key size used for this key pairs, ie, 1024")]
    param_key_size: String,
    #[arg(long)]
    #[arg(help = "specify the email of admin which this key bounds to")]
    email: String,
    #[arg(long)]
    #[arg(value_enum)]
    #[arg(help = "specify the key type for generating")]
    key_type: sign_identity::KeyType,
}

#[tokio::main]
async fn main() -> Result<()> {
    //prepare config and logger
    env_logger::init();
    let app = App::parse();
    let path = app.config.unwrap_or(format!("{}/{}", env::current_dir().expect("current dir not found").display(),
                                            "config/server.toml"));
    let server_config = util::config::ServerConfig::new(path);
    let control_server = presentation::server::control_server::ControlServer::new(server_config.config).await?;
    //handle commands
    match app.command {
        Some(Commands::CreateAdmin(create_admin)) => {
            let token = control_server.create_user_token(&User::new(create_admin.email.clone())?).await?;
            info!("[Result]: Administrator {} has been successfully created with token {} will expire {}", &create_admin.email, &token.token, &token.expire_at)
        }
        Some(Commands::GenerateKeys(generate_keys)) => {
            let user = control_server.get_user_by_email(&generate_keys.email).await?;
            let mut attributes = HashMap::new();
            attributes.insert("key_type".to_string(), generate_keys.param_key_type);
            attributes.insert("key_length".to_string(), generate_keys.param_key_size);
            let now = Utc::now();
            let key = DataKeyDTO {
                id: 0,
                name: generate_keys.name,
                description: generate_keys.description,
                user: user.id,
                email: user.email.clone(),
                attributes,
                key_type: generate_keys.key_type.to_string(),
                create_at: format!("{}", now),
                expire_at: format!("{}", now + Duration::days(30)),
                key_state: Default::default(),
            };

            let keys = control_server.create_keys(&mut DataKey::convert_from(key, UserIdentity::from(user))?).await?;
            info!("[Result]: Keys {} type {} has been successfully generated", &keys.name, &generate_keys.key_type)
        }
        None => {}
    };
    Ok(())
}
