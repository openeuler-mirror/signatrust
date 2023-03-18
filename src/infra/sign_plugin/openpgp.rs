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

use crate::domain::sign_plugin::SignPlugins;

use crate::util::error::{Error, Result};
use chrono::{DateTime, Utc};
use pgp::composed::signed_key::{SignedSecretKey, SignedPublicKey};
use pgp::composed::{key::SecretKeyParamsBuilder, KeyType};
use pgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::packet::SignatureConfig;
use pgp::packet::*;

use pgp::types::KeyTrait;
use pgp::types::{CompressionAlgorithm, SecretKeyTrait};
use pgp::Deserializable;
use serde::Deserialize;
use smallvec::*;

use std::collections::HashMap;

use std::io::{Cursor};
use std::str::from_utf8;


use validator::{Validate, ValidationError};
use pgp::composed::StandaloneSignature;
use crate::domain::datakey::entity::SecDataKey;

const DETACHED_SIGNATURE: &str = "detached";

#[derive(Debug, Validate, Deserialize)]
pub struct PgpKeyGenerationParameter {
    #[validate(length(min = 4, max = 20, message="invalid openpgp attribute 'name'"))]
    name: String,
    #[validate(email(message="openpgp attribute 'email'"))]
    email: String,
    #[validate(custom( function = "validate_key_type", message="invalid openpgp attribute 'key_type'"))]
    key_type: String,
    #[validate(custom(function = "validate_key_size", message="invalid openpgp attribute 'key_length'"))]
    key_length: String,
    #[validate(custom(function = "validate_utc_time", message="invalid openpgp attribute 'created_at'"))]
    create_at: String,
    #[validate(custom(function= "validate_utc_time", message="invalid openpgp attribute 'expire_at'"))]
    expire_at: String,
}

impl PgpKeyGenerationParameter {
    pub fn get_key(&self) -> Result<KeyType> {
        return match self.key_type.as_str() {
            "rsa" => Ok(KeyType::Rsa(self.key_length.parse::<u32>()?)),
            "ecdh" => Ok(KeyType::ECDH),
            "eddsa" => Ok(KeyType::EdDSA),
            _ => Err(Error::ParameterError(
                "invalid key type for openpgp".to_string(),
            )),
        };
    }

    pub fn get_user_id(&self) -> String {
        format!("{} <{}>", self.name, self.email)
    }
}

fn validate_key_type(key_type: &str) -> std::result::Result<(), ValidationError> {
    if !vec!["rsa", "ecdh", "eddsa"].contains(&key_type) {
        return Err(ValidationError::new("invalid key type"));
    }
    Ok(())
}

fn validate_key_size(key_size: &str) -> std::result::Result<(), ValidationError> {
    if !vec!["2048", "3072", "4096"].contains(&key_size) {
        return Err(ValidationError::new("invalid key size"));
    }
    Ok(())
}

fn validate_utc_time(expire: &str) -> std::result::Result<(), ValidationError> {
    let now = Utc::now();
    match expire.parse::<DateTime<Utc>>() {
        Ok(expire) => {
            if expire <= now {
                return Err(ValidationError::new("expire time less than current time"))
            }
        },
        Err(_e) => {
            return Err(ValidationError::new("failed to parse time string to utc"));
        }
    }
    Ok(())
}

pub struct OpenPGPPlugin {
    secret_key: SignedSecretKey,
    public_key: SignedPublicKey,
    identity: String,
}

impl OpenPGPPlugin {
    pub fn attributes_validate(attr: &HashMap<String, String>) -> Result<PgpKeyGenerationParameter> {
        let parameter: PgpKeyGenerationParameter =
            serde_json::from_str(serde_json::to_string(&attr)?.as_str())?;
        match parameter.validate() {
            Ok(_) => Ok(parameter),
            Err(e) => Err(Error::ParameterError(format!("{:?}", e))),
        }
    }
}

impl SignPlugins for OpenPGPPlugin {
    fn new(db: &SecDataKey) -> Result<Self> {
        let private = from_utf8(&db.private_key.unsecure()).map_err(|e| Error::KeyParseError(e.to_string()))?;
        let (secret_key, _) =
            SignedSecretKey::from_string(private).map_err(|e| Error::KeyParseError(e.to_string()))?;
        let public = from_utf8(&db.public_key.unsecure()).map_err(|e| Error::KeyParseError(e.to_string()))?;
        let (public_key, _) =
            SignedPublicKey::from_string(public).map_err(|e| Error::KeyParseError(e.to_string()))?;
        Ok(Self {
            secret_key,
            public_key,
            identity: db.identity.clone(),
        })
    }

    fn parse_attributes(
        _private_key: Option<Vec<u8>>,
        _public_key: Option<Vec<u8>>,
        _certificate: Option<Vec<u8>>,
    ) -> HashMap<String, String> {
        todo!()
    }

    fn generate_keys(
        value: &HashMap<String, String>,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let parameter = OpenPGPPlugin::attributes_validate(value)?;
        let mut key_params = SecretKeyParamsBuilder::default();
        let create_at = parameter.create_at.parse()?;
        let expire :DateTime<Utc> = parameter.expire_at.parse()?;
        let duration: core::time::Duration = (expire - Utc::now()).to_std()?;
        key_params
            .key_type(parameter.get_key()?)
            .can_create_certificates(false)
            .can_sign(true)
            .primary_user_id(parameter.get_user_id())
            .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256,])
            .preferred_hash_algorithms(smallvec![HashAlgorithm::SHA2_256,])
            .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB,])
            .created_at(create_at)
            .expiration(Some(duration));
        let secret_key_params = key_params.build()?;
        let secret_key = secret_key_params.generate()?;
        let passwd_fn = || String::new();
        let signed_secret_key = secret_key.sign(passwd_fn)?;
        let public_key = signed_secret_key.public_key();
        let signed_public_key = public_key.sign(&signed_secret_key, passwd_fn)?;
        Ok((
            signed_secret_key.to_armored_bytes(None)?,
            signed_public_key.to_armored_bytes(None)?,
            vec![],
        ))
    }

    fn sign(&self, content: Vec<u8>, options: HashMap<String, String>) -> Result<Vec<u8>> {
        let passwd_fn = String::new;
        let now = Utc::now();
        let sig_cfg = SignatureConfig {
            version: SignatureVersion::V4,
            typ: SignatureType::Binary,
            pub_alg: self.public_key.primary_key.algorithm(),
            hash_alg: HashAlgorithm::SHA2_256,
            issuer: Some(self.secret_key.key_id()),
            created: Some(now),
            unhashed_subpackets: vec![],
            hashed_subpackets: vec![
                Subpacket::SignatureCreationTime(now),
                Subpacket::Issuer(self.secret_key.key_id()),
            ],
        };
        let read_cursor = Cursor::new(content);
        let signature_packet = sig_cfg
            .sign(&self.secret_key, passwd_fn, read_cursor)
            .map_err(|e| Error::SignError(self.identity.clone(), e.to_string()))?;


        //detached signature
        if let Some(detached) = options.get(DETACHED_SIGNATURE) {
            if detached == "true" {
                let standard_signature = StandaloneSignature::new(signature_packet);
                return Ok(standard_signature.to_armored_bytes(None)?)
            }
        }
        let mut signature_bytes = Vec::with_capacity(1024);
        let mut cursor = Cursor::new(&mut signature_bytes);
        write_packet(&mut cursor, &signature_packet)
            .map_err(|e| Error::SignError(self.identity.clone(), e.to_string()))?;
        Ok(signature_bytes)
    }
}
