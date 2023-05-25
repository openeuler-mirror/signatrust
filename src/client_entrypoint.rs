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
use std::env;
use crate::util::error::{Result, Error};
use clap::{Parser, Subcommand};
use crate::client::cmd::add;
use config::{Config, File};
use std::sync::{Arc, atomic::AtomicBool, RwLock};
use crate::client::cmd::traits::SignCommand;

mod util;
mod client;
mod domain;

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

#[derive(Parser)]
#[command(name = "signatrust-client")]
#[command(author = "TommyLike <tommylikehu@gmail.com>")]
#[command(version = "0.10")]
#[command(about = "Sign binary with specified key id", long_about = None)]
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
    #[command(about = "Create new signature for single file or all of the files in directory", long_about = None)]
    Add(add::CommandAdd),
}

fn main() -> Result<()> {
    //prepare config and logger
    env_logger::init();
    let app = App::parse();
    let path = app.config.unwrap_or(
        format!("{}/{}", env::current_dir().expect("current dir not found").display(), "client.toml"));
    let mut client = Config::default();
    client
        .merge(File::with_name(path.as_str())).expect("load client configuration file");
    let signal = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&signal)).expect("failed to register sigterm signal");
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&signal)).expect("failed to register sigint signal");
    //construct handler
    let command = match app.command {
        Some(Commands::Add(add_command)) => {
            Some(add::CommandAddHandler::new(signal, Arc::new(RwLock::new(client)), add_command)?)
        }
        None => {None}
    };
    //handler and quit
    if let Some(handler) = command {
        handler.validate().expect("failed to validate command option");
        if !handler.handle().expect("failed to perform command") {
            return Err(Error::PartialSuccessError)
        }
    }
    Ok(())
}
