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

use super::entity::DataKey;
use crate::util::error::Result;
use async_trait::async_trait;
use crate::domain::datakey::entity::{KeyState};

#[async_trait]
pub trait Repository: Send + Sync {
    async fn create(&self, data_key: DataKey) -> Result<DataKey>;
    async fn get_all_keys(&self) -> Result<Vec<DataKey>>;
    async fn get_public_keys(&self) -> Result<Vec<DataKey>>;
    async fn get_private_keys(&self, user_id: i32) -> Result<Vec<DataKey>>;
    async fn get_by_id(&self, id: i32) -> Result<DataKey>;
    async fn get_by_name(&self, name: &String) -> Result<DataKey>;
    async fn update_state(&self, id: i32, state: KeyState) -> Result<()>;
    async fn get_enabled_key_by_type_and_name(&self, key_type: String, name: String) -> Result<DataKey>;
    async fn delete_private_key(&self, id: i32, user_id: i32) -> Result<()>;
    async fn request_delete_public_key(&self, user_id: i32, user_email: String, id: i32) -> Result<()>;
    async fn cancel_delete_public_key(&self, user_id: i32, id: i32) -> Result<()>;
}
