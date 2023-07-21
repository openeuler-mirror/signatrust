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
use std::fmt::{Display, Formatter};



#[derive(Debug, Clone)]
pub struct User {
    pub id: i32,
    pub email: String

}

impl Display for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id: {}, email: {}",
            self.id, self.email
        )
    }
}

impl User {
    pub fn new(email: String) -> Result<Self> {
        Ok(User {
            id: 0,
            email,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_user() {
        let user = User::new("test@example.com".to_string()).unwrap();
        assert_eq!(user.id, 0);
        assert_eq!(user.email, "test@example.com");
    }

    #[test]
    fn test_user_display() {
        let user = User::new("test@example.com".to_string()).unwrap();
        let expected = format!("id: {}, email: {}", user.id, user.email);
        assert_eq!(expected, format!("{}", user));
    }
}

