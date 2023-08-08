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
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use enum_iterator::{Sequence};
use serde::Deserialize;

pub const X509_VALID_KEY_SIZE: [&str; 3] = ["2048", "3072", "4096"];

#[derive(Debug, Clone, PartialEq, Sequence, Deserialize)]
pub enum X509KeyType {
    #[serde(rename = "rsa")]
    RSA,
    #[serde(rename = "dsa")]
    DSA,
}

impl FromStr for X509KeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "rsa" => Ok(X509KeyType::RSA),
            "dsa" => Ok(X509KeyType::DSA),
            _ => Err(Error::UnsupportedTypeError(format!("unsupported x509 key type {}", s))),
        }
    }
}

impl Display for X509KeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            X509KeyType::RSA => write!(f, "rsa"),
            X509KeyType::DSA => write!(f, "dsa"),
        }
    }
}

impl X509KeyType {
    pub fn get_real_key_type(&self, key_length: u32) -> Result<PKey<Private>> {
        match self {
            X509KeyType::RSA => Ok(PKey::from_rsa(Rsa::generate(key_length)?)?),
            X509KeyType::DSA => Ok(PKey::from_dsa(Dsa::generate(key_length)?)?),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Sequence, Deserialize)]
pub enum X509DigestAlgorithm {
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
}

impl Display for X509DigestAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            X509DigestAlgorithm::MD5 => write!(f, "md5"),
            X509DigestAlgorithm::SHA1 => write!(f, "sha1"),
            X509DigestAlgorithm::SHA2_224 => write!(f, "sha2_224"),
            X509DigestAlgorithm::SHA2_256 => write!(f, "sha2_256"),
            X509DigestAlgorithm::SHA2_384 => write!(f, "sha2_384"),
            X509DigestAlgorithm::SHA2_512 => write!(f, "sha2_512"),
        }
    }
}

impl FromStr for X509DigestAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "md5" => Ok(X509DigestAlgorithm::MD5),
            "sha1" => Ok(X509DigestAlgorithm::SHA1),
            "sha2_224" => Ok(X509DigestAlgorithm::SHA2_224),
            "sha2_256" => Ok(X509DigestAlgorithm::SHA2_256),
            "sha2_384" => Ok(X509DigestAlgorithm::SHA2_384),
            "sha2_512" => Ok(X509DigestAlgorithm::SHA2_512),
            _ => Err(Error::UnsupportedTypeError(format!("unsupported x509 digest algorithm {}", s))),
        }
    }
}

impl X509DigestAlgorithm {
    pub fn get_real_algorithm(&self) -> MessageDigest {
        match self {
            X509DigestAlgorithm::MD5 => MessageDigest::md5(),
            X509DigestAlgorithm::SHA1 => MessageDigest::sha1(),
            X509DigestAlgorithm::SHA2_224 => MessageDigest::sha224(),
            X509DigestAlgorithm::SHA2_256 => MessageDigest::sha256(),
            X509DigestAlgorithm::SHA2_384 => MessageDigest::sha384(),
            X509DigestAlgorithm::SHA2_512 => MessageDigest::sha512()
        }
    }
}
