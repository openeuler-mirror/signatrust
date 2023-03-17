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

use crate::util::error::Result;
use config::{Config, File, FileFormat};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc::channel;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc, RwLock};
use std::thread;
use std::time::Duration;

pub struct ServerConfig {
    pub config: Arc<RwLock<Config>>,
    path: String,
}

impl ServerConfig {
    pub fn new(path: String) -> ServerConfig {
        let builder = Config::builder()
            .set_default("tls_cert", "").expect("tls cert default to empty")
            .set_default("tls_key", "").expect("tls key default to empty")
            .set_default("ca_root", "").expect("ca root default to empty")
            .add_source(File::new(path.as_str(), FileFormat::Toml));
        let config = builder.build().expect("load configuration file");
        ServerConfig {
            config: Arc::new(RwLock::new(config)),
            path,
        }
    }
    pub fn watch(&self, signal: Arc<AtomicBool>) -> Result<()> {
        let (tx, rx) = channel();
        let watch_file = self.path.clone();
        let config = self.config.clone();
        let mut watcher: RecommendedWatcher = Watcher::new(
            tx,
            notify::Config::default().with_poll_interval(Duration::from_secs(5)),
        )
        .expect("configure file watch failed to setup");
        thread::spawn(move || {
            watcher
                .watch(Path::new(watch_file.as_str()), RecursiveMode::NonRecursive)
                .expect("failed to watch configuration file");
            //TODO: handle signal correctly
            while !signal.load(Ordering::Relaxed) {
                match rx.recv() {
                    Ok(Ok(Event {
                        kind: notify::event::EventKind::Modify(_),
                        ..
                    })) => {
                        info!("server configuration changed ...");
                        config
                            .write()
                            .unwrap()
                            .refresh()
                            .expect("failed to write configuration file");
                    }
                    Err(e) => error!("watch error: {:?}", e),
                    _ => {}
                }
            }
            info!("signal received, will quit");
        });
        Ok(())
    }
}
