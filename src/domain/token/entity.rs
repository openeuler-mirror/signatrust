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

const TOKEN_EXPIRE_IN_DAYS: i64 = 365;

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub id: i32,
    pub user_id: i32,
    pub description: String,
    pub token: String,
    pub create_at: DateTime<Utc>,
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
    pub fn new(user_id: i32, description: String, token: String) -> Result<Self> {
        let now = Utc::now();
        Ok(Token {
            id: 0,
            user_id,
            description,
            token,
            create_at: now,
            expire_at: now + Duration::days(TOKEN_EXPIRE_IN_DAYS),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_token() {
        let token = Token::new(1, "Test".to_string(), "abc123".to_string()).unwrap();
        assert_eq!(token.id, 0);
        assert_eq!(token.user_id, 1);
        assert_eq!(token.description, "Test");
        assert_eq!(token.token, "abc123");
        assert!(token.create_at < Utc::now());
        assert_eq!(token.expire_at, token.create_at + Duration::days(TOKEN_EXPIRE_IN_DAYS));
    }

    #[test]
    fn test_token_display() {
        let token = Token::new(1, "Test".to_string(), "abc123".to_string()).unwrap();
        let expected = format!("id: {}, user_id: {}, expire_at: {}",
                               token.id, token.user_id, token.expire_at);
        assert_eq!(expected, format!("{}", token));
    }
}

