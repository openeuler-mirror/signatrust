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

use crate::util::error::Result;
use config::{Config, File, FileFormat};
use notify::{Error, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub struct ServerConfig {
    pub config: Arc<RwLock<Config>>,
    path: String,
}

impl ServerConfig {
    pub fn new(path: String) -> ServerConfig {
        let builder = Config::builder()
            .set_default("tls_cert", "")
            .expect("tls cert default to empty")
            .set_default("tls_key", "")
            .expect("tls key default to empty")
            .set_default("ca_root", "")
            .expect("ca root default to empty")
            .add_source(File::new(path.as_str(), FileFormat::Toml));
        let config = builder.build().expect("load configuration file");
        ServerConfig {
            config: Arc::new(RwLock::new(config)),
            path,
        }
    }
    pub fn watch(&self, cancel_token: CancellationToken) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(10);
        let watch_file = self.path.clone();
        let config = self.config.clone();
        let mut watcher: RecommendedWatcher = RecommendedWatcher::new(
            move |result: std::result::Result<Event, Error>| {
                tx.blocking_send(result).expect("Failed to send event");
            },
            notify::Config::default().with_poll_interval(Duration::from_secs(5)),
        )
        .expect("configure file watch failed to setup");
        watcher
            .watch(Path::new(watch_file.as_str()), RecursiveMode::NonRecursive)
            .expect("failed to watch configuration file");
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        info!("cancel token received, will quit configuration watcher");
                        break;
                    }
                    event = rx.recv() => {
                        match event {
                            Some(Ok(Event {
                                kind: notify::event::EventKind::Modify(_),
                                ..
                            })) => {
                                info!("server configuration changed ...");
                                let mut conf = config.write().unwrap();
                                *conf = Config::builder().add_source(File::with_name(watch_file.as_str())).build_cloned().expect("reloading from configuration file");
                            }
                            Some(Err(e)) => error!("watch error: {:?}", e),
                            _ => {}
                        }
                    }
                }
            }
        });
        Ok(())
    }
}
