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

use crate::client::{sign_identity::SignIdentity};


use crate::client::worker::traits::SignHandler;
use crate::client::file_handler::traits::FileHandler;
use async_trait::async_trait;
use crate::util::error;

pub struct Splitter {
}


impl Splitter {

    pub fn new() -> Self {
        Self {
        }
    }
}

#[async_trait]
impl SignHandler for Splitter {
    async fn process(&mut self, handler: Box<dyn FileHandler>, item: SignIdentity) -> SignIdentity {
        let mut sign_options = item.sign_options.borrow().clone();
        match handler.split_data(&item.file_path, &mut sign_options).await {
            Ok(content) => {
                *item.raw_content.borrow_mut() = content;
                *item.sign_options.borrow_mut() = sign_options;
                debug!("successfully split file {}", item.file_path.as_path().display());
            }
            Err(err) => {
                *item.error.borrow_mut() = Err(error::Error::SplitFileError(format!("{:?}", err)))
            }
        }
        item
    }
}

