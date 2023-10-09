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

use crate::client::file_handler::factory::FileHandlerFactory;
use crate::client::file_handler::traits::FileHandler;
use crate::client::sign_identity::SignIdentity;
use async_channel::Sender;
use async_trait::async_trait;

#[async_trait]
pub trait SignHandler {
    async fn handle(&mut self, item: SignIdentity, sender: Sender<SignIdentity>) -> () {
        if item.error.borrow().clone().is_err() {
            if let Err(err) = sender.send(item).await {
                error!("failed to send sign object into channel: {}", err);
            }
        } else {
            let handler = FileHandlerFactory::get_handler(&item.file_type);
            let updated = self.process(handler, item).await;
            if let Err(err) = sender.send(updated).await {
                error!("failed to send sign object into channel: {}", err);
            }
        }
    }
    //NOTE: instead of raise out error for specific sign object out of method, we need record error inside of the SignIdentity object.
    async fn process(&mut self, handler: Box<dyn FileHandler>, item: SignIdentity) -> SignIdentity;
}
