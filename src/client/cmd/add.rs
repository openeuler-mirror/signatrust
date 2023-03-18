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

use clap::{Args};
use crate::util::error::Result;
use config::{Config};
use std::sync::{Arc, atomic::AtomicBool, RwLock};
use super::traits::SignCommand;
use std::path::PathBuf;
use tokio::runtime;
use crate::client::sign_identity;
use std::collections::HashMap;

use crate::util::error;
use async_channel::{bounded};

use crate::client::cmd::options;
use crate::client::file_handler::factory::FileHandlerFactory;

use crate::client::load_balancer::factory::ChannelFactory;
use crate::client::worker::assembler::Assembler;
use crate::client::worker::signer::RemoteSigner;
use crate::client::worker::splitter::Splitter;
use crate::client::worker::traits::SignHandler;
use std::sync::atomic::{AtomicI32, Ordering};

lazy_static! {
    pub static ref FILE_EXTENSION: HashMap<sign_identity::FileType, Vec<&'static str>> = HashMap::from([
        (sign_identity::FileType::RPM, vec!["rpm", "srpm"]),
        (sign_identity::FileType::CheckSum, vec!["txt", "sha256sum"]),
        (sign_identity::FileType::KernelModule, vec!["ko"]),
    ]);
}

#[derive(Args)]
pub struct CommandAdd {
    #[arg(long)]
    #[arg(value_enum)]
    #[arg(help = "specify the file type for signing, currently support checksum and rpm")]
    file_type: sign_identity::FileType,
    #[arg(long)]
    #[arg(value_enum)]
    #[arg(help = "specify the key type for signing, currently support pgp and x509")]
    key_type: sign_identity::KeyType,
    #[arg(long)]
    #[arg(help = "specify the key id for signing")]
    key_id: String,
    #[arg(long)]
    #[arg(help = "create detached signature")]
    detached: bool,
    #[arg(long)]
    #[arg(help = "skip signed file")]
    skip_signed: bool,
    #[arg(help = "specify the path which will be used for signing file and directory are supported")]
    path: String,
}


#[derive(Clone)]
pub struct CommandAddHandler {
    worker_threads: usize,
    working_dir: String,
    file_type: sign_identity::FileType,
    key_type: sign_identity::KeyType,
    key_id: String,
    path: PathBuf,
    buffer_size: usize,
    signal: Arc<AtomicBool>,
    config:  Arc<RwLock<Config>>,
    detached: bool,
    skip_signed: bool,
    max_concurrency: usize
}

impl CommandAddHandler {

    fn get_sign_options(&self) -> HashMap<String, String> {
        HashMap::from([
            (options::DETACHED.to_string(), self.detached.to_string()),
            (options::SKIP_SIGNED.to_string(), self.skip_signed.to_string()),
            (options::KEY_TYPE.to_string(), self.key_type.to_string())])
    }
    fn collect_file_candidates(&self) -> Result<Vec<sign_identity::SignIdentity>> {
        if self.path.is_dir() {
            let mut container = Vec::new();
            for entry in walkdir::WalkDir::new(self.path.to_str().unwrap()) {
                match entry {
                    Ok(en)=> {
                        if en.metadata()?.is_dir() {
                            continue
                        }
                        if let Some(extension) = en.path().extension() {
                            if self.file_candidates(extension.to_str().unwrap())? {
                                container.push(
                                    sign_identity::SignIdentity::new(
                                        self.file_type.clone(),
                                        en.path().to_path_buf(),
                                        self.key_type.clone(),
                                        self.key_id.clone(),
                                        self.get_sign_options()));
                            }
                        }
                    },
                    Err(err)=> {
                        error!("failed to scan file {}, will be skipped", err);
                    }
                }
            }
            return Ok(container);
        } else if self.file_candidates(self.path.extension().unwrap().to_str().unwrap())? {
                return Ok(vec![sign_identity::SignIdentity::new(
                    self.file_type.clone(), self.path.clone(), self.key_type.clone(), self.key_id.clone(), self.get_sign_options())]);
        }
        Err(error::Error::NoFileCandidateError)
    }

    fn file_candidates(&self, extension: &str) -> Result<bool> {
        let collections = FILE_EXTENSION.get(
            &self.file_type).ok_or(
            error::Error::FileNotSupportError(format!("{}", self.file_type)))?;
        if collections.contains(&extension) {
            return Ok(true)
        }
        Ok(false)
    }
}


impl SignCommand for CommandAddHandler {
    type CommandValue = CommandAdd;

    fn new(signal: Arc<AtomicBool>, config: Arc<RwLock<Config>>, command: Self::CommandValue) -> Result<Self> {
        let mut worker_threads = config.read()?.get_string("worker_threads")?.parse()?;
        if worker_threads == 0 {
            worker_threads = num_cpus::get() as usize;
        }
        Ok(CommandAddHandler{
            worker_threads,
            buffer_size: config.read()?.get_string("buffer_size")?.parse()?,
            working_dir: config.read()?.get_string("working_dir")?,
            file_type: command.file_type,
            key_type: command.key_type,
            key_id: command.key_id,
            path: std::path::PathBuf::from(&command.path),
            signal,
            config: config.clone(),
            detached: command.detached,
            skip_signed: command.skip_signed,
            max_concurrency: config.read()?.get_string("max_concurrency")?.parse()?,
        })
    }

    fn validate(&self) -> Result<()> {
        FileHandlerFactory::get_handler(&self.file_type).validate_options(&self.get_sign_options())
    }

    //Signing process are described below.
    //1. fetch all file candidates by walk through the specified path and filter by file extension.
    //2. split files via file handler
    //3. send split content to signer handler which will do remote sign internally
    //4. send encrypted content to file handler for assemble
    //5. collect sign result and print
    //6. wait for async task finish
    //7. all of the worker will not *raise* error but record error inside of object
    //            vector                sign_chn                      assemble_chn             collect_chn
    //  fetcher-----------splitter * N----------remote signer * N---------------assembler * N--------------collector * N
    fn handle(&self) -> Result<bool> {
        let files = self.collect_file_candidates()?;
        let succeed_files = Arc::new(AtomicI32::new(0));
        let failed_files = Arc::new(AtomicI32::new(0));
        let runtime = runtime::Builder::new_multi_thread()
            .worker_threads(self.worker_threads)
            .enable_io()
            .enable_time()
            .build().unwrap();
        let (split_s, split_r) = bounded::<sign_identity::SignIdentity>(self.max_concurrency);
        let (sign_s, sign_r) = bounded::<sign_identity::SignIdentity>(self.max_concurrency);
        let (assemble_s, assemble_r) = bounded::<sign_identity::SignIdentity>(self.max_concurrency);
        let (collect_s, collect_r) = bounded::<sign_identity::SignIdentity>(self.max_concurrency);
        info!("starting to sign {} files", files.len());
        let lb_config = self.config.read()?.get_table("server")?;
        runtime.block_on(async {
            let channel = ChannelFactory::new(
                &lb_config).await.unwrap().get_channel().unwrap();
            let mut signer = RemoteSigner::new(channel, self.buffer_size);
            //split file
            let send_handlers = files.into_iter().map(|file|{
                let task_split_s = split_s.clone();
                tokio::spawn(async move {
                    let file_name = format!("{}", file.file_path.as_path().display());
                    if let Err(err) = task_split_s.send(file).await {
                        error!("failed to send file for splitting: {}", err);
                    } else {
                        info!("starting to split file: {}", file_name);
                    }

                })
            }).collect::<Vec<_>>();
            //do file split
            let task_sign_s = sign_s.clone();
            let split_handler = tokio::spawn(async move {
                loop {
                    let sign_identity = split_r.recv().await;
                    match sign_identity {
                        Ok(identity) => {
                            let mut splitter = Splitter::new();
                            splitter.handle(identity, task_sign_s.clone()).await;
                        },
                        Err(_) => {
                            info!("split channel closed");
                            return
                        }
                    }
                }
            });
            //do remote sign
            let task_assemble_s = assemble_s.clone();
            let sign_handler = tokio::spawn(async move {
                loop {
                    let sign_identity = sign_r.recv().await;
                    match sign_identity {
                        Ok(identity) => {
                            signer.handle(identity, task_assemble_s.clone()).await;
                        },
                        Err(_) => {
                            info!("sign channel closed");
                            return
                        }
                    }
                }
            });
            //assemble file
            let working_dir = self.working_dir.clone();
            let task_collect_s = collect_s.clone();
            let assemble_handler = tokio::spawn(async move {
                loop {
                    let sign_identity = assemble_r.recv().await;
                    match sign_identity {
                        Ok(identity) => {
                            let mut assembler = Assembler::new( working_dir.clone());
                            assembler.handle(identity, task_collect_s.clone()).await;
                        },
                        Err(_) => {
                            info!("assemble channel closed");
                            return
                        }
                    }
                }
            });
            // collect result
            let succeed_files_c = succeed_files.clone();
            let failed_files_c = failed_files.clone();
            let collect_handler = tokio::spawn(async move {
                loop {
                    let sign_identity = collect_r.recv().await;
                    match sign_identity {
                        Ok(identity) => {
                            if identity.error.borrow().clone().is_err() {
                                error!("failed to sign file {} due to error {:?}",
                                    identity.file_path.as_path().display(),
                                    identity.error.borrow().clone().err());
                                failed_files_c.fetch_add( 1, Ordering::SeqCst);
                            } else {
                                info!("successfully signed file {}", identity.file_path.as_path().display());
                                succeed_files_c.fetch_add( 1, Ordering::SeqCst);
                            }
                        },
                        Err(_) => {
                            info!("collect channel closed");
                            return
                        }
                    }
                }
            });
            // wait for finish
            for h in send_handlers {
                h.await.unwrap();
            }
            drop(split_s);
            split_handler.await.expect("split worker finished correctly");
            drop(sign_s);
            sign_handler.await.expect("sign worker finished correctly");
            drop(assemble_s);
            assemble_handler.await.expect("assemble worker finished correctly");
            drop(collect_s);
            collect_handler.await.expect("collect worker finished correctly");
            info!("Successfully signed {} files failed {} files",
                succeed_files.load(Ordering::Relaxed), failed_files.load(Ordering::Relaxed));
            info!("sign files process finished");
        });
        if failed_files.load(Ordering::Relaxed) != 0 {
            return Ok(false)
        }
        Ok(true)
    }
}
