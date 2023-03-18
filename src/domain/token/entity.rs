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

use chrono::{DateTime, Duration, Utc};
use std::fmt::{Display, Formatter};


use crate::util::key::generate_api_token;

const TOKEN_EXPIRE_IN_DAYS: i64 = 180;

#[derive(Debug)]
pub struct Token {
    pub id: i32,
    pub user_id: i32,
    pub token: String,
    pub expire_at: DateTime<Utc>,
}

impl Display for Token {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id: {}, user_id: {}, expire_at: {}",
            self.id, self.user_id, self.expire_at
        )
    }
}

impl Token {
    pub fn new(user_id: i32) -> Result<Self> {
        let now = Utc::now();
        Ok(Token {
            id: 0,
            user_id,
            token: generate_api_token(),
            expire_at: now + Duration::days(TOKEN_EXPIRE_IN_DAYS),
        })
    }
}
