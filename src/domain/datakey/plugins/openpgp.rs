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

use std::str::FromStr;
use crate::util::error::{Error, Result};
use std::fmt::{Display, Formatter};
use std::fmt;
use pgp::composed::{KeyType};
use pgp::crypto::{hash::HashAlgorithm};
use enum_iterator::{Sequence};
use serde::Deserialize;

pub const PGP_VALID_KEY_SIZE: [&str; 3] = ["2048", "3072", "4096"];

#[derive(Debug, Clone, PartialEq, Sequence, Deserialize)]
pub enum OpenPGPKeyType {
    #[serde(rename = "rsa")]
    Rsa,
    #[serde(rename = "eddsa")]
    Eddsa,
}

impl FromStr for OpenPGPKeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "rsa" => Ok(OpenPGPKeyType::Rsa),
            "eddsa" => Ok(OpenPGPKeyType::Eddsa),
            _ => Err(Error::UnsupportedTypeError(format!("unsupported openpgp key state {}", s))),
        }
    }
}

impl Display for OpenPGPKeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            OpenPGPKeyType::Rsa => write!(f, "rsa"),
            OpenPGPKeyType::Eddsa => write!(f, "eddsa"),
        }
    }
}

impl OpenPGPKeyType {
    //key length defaults to 2048
    pub fn get_real_key_type(&self, key_length: Option<String>) -> KeyType {
        match self {
           OpenPGPKeyType::Rsa => {
               if let Some(length) = key_length {
                   KeyType::Rsa(length.parse().unwrap())
               } else {
                   KeyType::Rsa(2048)
               }
           },
           OpenPGPKeyType::Eddsa => KeyType::EdDSA
        }
    }
}

#[derive(Debug, Clone, PartialEq, Sequence, Deserialize)]
pub enum OpenPGPDigestAlgorithm {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "md5")]
    MD5,
    #[serde(rename = "sha1")]
    SHA1,
    #[serde(rename = "sha2_224")]
    SHA2_224,
    #[serde(rename = "sha2_256")]
    SHA2_256,
    #[serde(rename = "sha2_384")]
    SHA2_384,
    #[serde(rename = "sha2_512")]
    SHA2_512,
    #[serde(rename = "sha3_256")]
    SHA3_256,
    #[serde(rename = "sha3_512")]
    SHA3_512,
}

impl Display for OpenPGPDigestAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            OpenPGPDigestAlgorithm::None => write!(f, "none"),
            OpenPGPDigestAlgorithm::MD5 => write!(f, "md5"),
            OpenPGPDigestAlgorithm::SHA1 => write!(f, "sha1"),
            OpenPGPDigestAlgorithm::SHA2_224 => write!(f, "sha2_224"),
            OpenPGPDigestAlgorithm::SHA2_256 => write!(f, "sha2_256"),
            OpenPGPDigestAlgorithm::SHA2_384 => write!(f, "sha2_384"),
            OpenPGPDigestAlgorithm::SHA2_512 => write!(f, "sha2_512"),
            OpenPGPDigestAlgorithm::SHA3_256 => write!(f, "sha3_256"),
            OpenPGPDigestAlgorithm::SHA3_512 => write!(f, "sha3_512"),
        }
    }
}

impl FromStr for OpenPGPDigestAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "none" => Ok(OpenPGPDigestAlgorithm::None),
            "md5" => Ok(OpenPGPDigestAlgorithm::MD5),
            "sha1" => Ok(OpenPGPDigestAlgorithm::SHA1),
            "sha2_224" => Ok(OpenPGPDigestAlgorithm::SHA2_224),
            "sha2_256" => Ok(OpenPGPDigestAlgorithm::SHA2_256),
            "sha2_384" => Ok(OpenPGPDigestAlgorithm::SHA2_384),
            "sha2_512" => Ok(OpenPGPDigestAlgorithm::SHA2_512),
            "sha3_256" => Ok(OpenPGPDigestAlgorithm::SHA3_256),
            "sha3_512" => Ok(OpenPGPDigestAlgorithm::SHA3_512),
            _ => Err(Error::UnsupportedTypeError(format!("unsupported openpgp digest algorithm {}", s))),
        }
    }
}

impl OpenPGPDigestAlgorithm {
    pub fn get_real_algorithm(&self) -> HashAlgorithm {
        match self {
            OpenPGPDigestAlgorithm::None => HashAlgorithm::None,
            OpenPGPDigestAlgorithm::MD5 => HashAlgorithm::MD5,
            OpenPGPDigestAlgorithm::SHA1=> HashAlgorithm::SHA1,
            OpenPGPDigestAlgorithm::SHA2_224 => HashAlgorithm::SHA2_224,
            OpenPGPDigestAlgorithm::SHA2_256 => HashAlgorithm::SHA2_256,
            OpenPGPDigestAlgorithm::SHA2_384 => HashAlgorithm::SHA2_384,
            OpenPGPDigestAlgorithm::SHA2_512 => HashAlgorithm::SHA2_512,
            OpenPGPDigestAlgorithm::SHA3_256 => HashAlgorithm::SHA3_256,
            OpenPGPDigestAlgorithm::SHA3_512 => HashAlgorithm::SHA3_512,
        }
    }
}
