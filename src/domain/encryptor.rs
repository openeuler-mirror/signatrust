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

use crate::util::error::{Error, Result};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub enum Algorithm {
    Aes256GSM,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Algorithm::Aes256GSM => write!(f, "Aes256GSM"),
        }
    }
}

impl FromStr for Algorithm {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "aes256gsm" => Ok(Algorithm::Aes256GSM),
            _ => Err(Error::UnsupportedTypeError(format!(
                "{} invalid encryption algorithm type",
                s
            ))),
        }
    }
}

pub trait Encryptor: Send + Sync {
    fn generate_key(&self) -> Vec<u8>;
    fn algorithm(&self) -> Algorithm;
    fn encrypt(&self, key: Vec<u8>, content: Vec<u8>) -> Result<Vec<u8>>;
    fn decrypt(&self, key: Vec<u8>, content: Vec<u8>) -> Result<Vec<u8>>;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_algorithm_from_string_and_display() {
        let _ = Algorithm::from_str("invalid_algorithm").expect_err("algorithm from invalid string should fail");
        let algorithm = Algorithm::from_str("aes256gsm").expect("algorithm from string failed");
        assert_eq!(format!("{}", algorithm), "Aes256GSM");
    }
}

