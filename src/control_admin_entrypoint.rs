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
use crate::util::sign::KeyType;
use clap::{Parser, Subcommand};
use clap::{Args};
use crate::domain::datakey::entity::{DataKey};
use crate::domain::user::entity::User;
use crate::presentation::handler::control::model::datakey::dto::{CreateDataKeyDTO};
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
    GenerateKeys(Box<CommandGenerateKeys>),
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
    #[arg(help = "specify the type of internal key used for keys generation, ie, rsa")]
    param_key_type: String,
    #[arg(long)]
    #[arg(help = "specify the type of internal key used for keys generation, ie, 1024")]
    param_key_size: String,
    #[arg(long)]
    #[arg(help = "specify the type of digest algorithm used for signing, ie, sha1")]
    digest_algorithm: String,
    //pgp specific parameters
    #[arg(long)]
    #[arg(help = "specify the email used for openPGP key generation. ")]
    param_pgp_email: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the passphrase for openPGP key generation. ")]
    param_pgp_passphrase: Option<String>,
    //x509 specific parameters
    #[arg(long)]
    #[arg(help = "specify the 'CommonName' used for x509 key generation. ")]
    param_x509_common_name: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the 'OrganizationalUnit' used for x509 key generation. ")]
    param_x509_organizational_unit: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the 'Organization' used for x509 key generation. ")]
    param_x509_organization: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the 'Locality' used for x509 key generation. ")]
    param_x509_locality: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the 'ProvinceName' used for x509 key generation. ")]
    param_x509_province_name: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the 'CountryName' used for x509 key generation. ")]
    param_x509_country_name: Option<String>,
    #[arg(long)]
    #[arg(help = "specify the email of admin which this key bounds to")]
    email: String,
    #[arg(long)]
    #[arg(value_enum)]
    #[arg(help = "specify th type of key")]
    key_type: KeyType,
}

fn generate_keys_parameters(command: &CommandGenerateKeys) -> HashMap<String, String> {
    let mut attributes = HashMap::new();
    attributes.insert("key_type".to_string(), command.param_key_type.clone());
    attributes.insert("key_length".to_string(), command.param_key_size.clone());
    attributes.insert("digest_algorithm".to_string(), command.digest_algorithm.clone());
    if command.key_type == KeyType::Pgp {
        attributes.insert("email".to_string(), command.param_pgp_email.clone().unwrap());
        attributes.insert("passphrase".to_string(), command.param_pgp_passphrase.clone().unwrap());
    } else if command.key_type == KeyType::X509 {
        attributes.insert("common_name".to_string(), command.param_x509_common_name.clone().unwrap());
        attributes.insert("country_name".to_string(), command.param_x509_country_name.clone().unwrap());
        attributes.insert("locality".to_string(), command.param_x509_locality.clone().unwrap());
        attributes.insert("province_name".to_string(), command.param_x509_province_name.clone().unwrap());
        attributes.insert("organization".to_string(), command.param_x509_organization.clone().unwrap());
        attributes.insert("organizational_unit".to_string(), command.param_x509_organizational_unit.clone().unwrap());
    }
    attributes
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
            let token = control_server.create_user_token(User::new(create_admin.email.clone())?).await?;
            info!("[Result]: Administrator {} has been successfully created with token {} will expire {}", &create_admin.email, &token.token, &token.expire_at)
        }
        Some(Commands::GenerateKeys(generate_keys)) => {
            let user = control_server.get_user_by_email(&generate_keys.email).await?;

            let now = Utc::now();
            let key = CreateDataKeyDTO {
                name: generate_keys.name.clone(),
                description: generate_keys.description.clone(),
                visibility: "public".to_string(),
                attributes: generate_keys_parameters(&generate_keys),
                key_type: generate_keys.key_type.to_string(),
                expire_at: format!("{}", now + Duration::days(30)),
            };

            let keys = control_server.create_keys(&mut DataKey::create_from(key, UserIdentity::from(user))?).await?;
            info!("[Result]: Keys {} type {} has been successfully generated", &keys.name, &generate_keys.key_type)
        }
        None => {}
    };
    Ok(())
}
