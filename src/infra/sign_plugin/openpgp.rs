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
use crate::util::options;
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
use crate::domain::datakey::entity::{DataKey, DataKeyContent, SecDataKey};
use crate::util::key::encode_u8_to_hex_string;
use super::util::{validate_utc_time_not_expire, validate_utc_time, attributes_validate};

#[derive(Debug, Validate, Deserialize)]
pub struct PgpKeyImportParameter {
    #[validate(custom( function = "validate_key_type", message="invalid openpgp attribute 'key_type'"))]
    key_type: String,
    #[validate(custom(function = "validate_key_size", message="invalid openpgp attribute 'key_length'"))]
    key_length: String,
    #[validate(custom(function= "validate_digest_algorithm_type", message="invalid digest algorithm"))]
    digest_algorithm: String,
    #[validate(custom(function = "validate_utc_time", message="invalid openpgp attribute 'create_at'"))]
    create_at: String,
    #[validate(custom(function= "validate_utc_time_not_expire", message="invalid openpgp attribute 'expire_at'"))]
    expire_at: String,
    passphrase: Option<String>
}


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
    #[validate(custom(function= "validate_digest_algorithm_type", message="invalid digest algorithm"))]
    digest_algorithm: String,
    #[validate(custom(function = "validate_utc_time", message="invalid openpgp attribute 'create_at'"))]
    create_at: String,
    #[validate(custom(function= "validate_utc_time_not_expire", message="invalid openpgp attribute 'expire_at'"))]
    expire_at: String,
    passphrase: Option<String>
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

pub fn get_digest_algorithm(hash_digest: &str) -> Result<HashAlgorithm> {
    match hash_digest {
        "none" => Ok(HashAlgorithm::None),
        "md5" => Ok(HashAlgorithm::MD5),
        "sha1" => Ok(HashAlgorithm::SHA1),
        "sha2_256" => Ok(HashAlgorithm::SHA2_256),
        "sha2_384" => Ok(HashAlgorithm::SHA2_384),
        "sha2_512" => Ok(HashAlgorithm::SHA2_512),
        "sha2_224" => Ok(HashAlgorithm::SHA2_224),
        "sha3_256" => Ok(HashAlgorithm::SHA3_256),
        "sha3_512" => Ok(HashAlgorithm::SHA3_512),
        _ => Err(Error::ParameterError(
            "invalid digest algorithm for openpgp".to_string(),
        )),
    }
}

fn validate_key_type(key_type: &str) -> std::result::Result<(), ValidationError> {
    if !vec!["rsa", "ecdh", "eddsa"].contains(&key_type) {
        return Err(ValidationError::new("invalid key type, possible values are rsa/ecdh/eddsa"));
    }
    Ok(())
}

fn validate_digest_algorithm_type(key_type: &str) -> std::result::Result<(), ValidationError> {
    if !vec!["none", "md5", "sha1", "sha1", "sha2_256", "sha2_384","sha2_512","sha2_224","sha3_256", "sha3_512"].contains(&key_type) {
        return Err(ValidationError::new("invalid hash algorithm, possible values are none/md5/sha1/sha1/sha2_256/sha2_384/sha2_512/sha2_224/sha3_256/sha3_512"));
    }
    Ok(())
}

fn validate_key_size(key_size: &str) -> std::result::Result<(), ValidationError> {
    if !vec!["2048", "3072", "4096"].contains(&key_size) {
        return Err(ValidationError::new("invalid key size, possible values are 2048/3072/4096"));
    }
    Ok(())
}

pub struct OpenPGPPlugin {
    secret_key: SignedSecretKey,
    public_key: SignedPublicKey,
    identity: String,
    attributes: HashMap<String, String>
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
    fn new(db: SecDataKey) -> Result<Self> {
        let private = from_utf8(db.private_key.unsecure()).map_err(|e| Error::KeyParseError(e.to_string()))?;
        let (secret_key, _) =
            SignedSecretKey::from_string(private).map_err(|e| Error::KeyParseError(e.to_string()))?;
        let public = from_utf8(db.public_key.unsecure()).map_err(|e| Error::KeyParseError(e.to_string()))?;
        let (public_key, _) =
            SignedPublicKey::from_string(public).map_err(|e| Error::KeyParseError(e.to_string()))?;
        Ok(Self {
            secret_key,
            public_key,
            identity: db.identity.clone(),
            attributes: db.attributes,
        })
    }

    fn validate_and_update(key: &mut DataKey) -> Result<()> where Self: Sized {
        let _ = attributes_validate::<PgpKeyImportParameter>(&key.attributes)?;
        //validate the digest
        if let Some(digest_str) = key.attributes.get("digest_algorithm") {
            let _ = get_digest_algorithm(digest_str)?;
        }
        //validate keys
        let private = from_utf8(&key.private_key).map_err(|e| Error::KeyParseError(e.to_string()))?;
        let (secret_key, _) =
            SignedSecretKey::from_string(private).map_err(|e| Error::KeyParseError(e.to_string()))?;
        let public = from_utf8(&key.public_key).map_err(|e| Error::KeyParseError(e.to_string()))?;
        let (public_key, _) =
            SignedPublicKey::from_string(public).map_err(|e| Error::KeyParseError(e.to_string()))?;
        //update key attributes
        key.fingerprint = encode_u8_to_hex_string(&secret_key.fingerprint());
        match public_key.expires_at() {
            None => {}
            Some(time) => {
                key.expire_at = time
            }
        }
        Ok(())
    }

    fn parse_attributes(
        _private_key: Option<Vec<u8>>,
        _public_key: Option<Vec<u8>>,
        _certificate: Option<Vec<u8>>,
    ) -> HashMap<String, String> {
        todo!()
    }

    fn generate_keys(
        attributes: &HashMap<String, String>,
    ) -> Result<DataKeyContent> {
        let parameter = attributes_validate::<PgpKeyGenerationParameter>(attributes)?;
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
            .preferred_hash_algorithms(smallvec![get_digest_algorithm(parameter.digest_algorithm.as_str())?])
            .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB,])
            .created_at(create_at)
            .expiration(Some(duration));
        let secret_key_params = key_params.build()?;
        let secret_key = secret_key_params.generate()?;
        let passwd_fn= || match parameter.passphrase {
            None => {
                String::new()
            }
            Some(password) => {
                password
            }
        };
        let signed_secret_key = secret_key.sign(passwd_fn.clone())?;
        let public_key = signed_secret_key.public_key();
        let signed_public_key = public_key.sign(&signed_secret_key, passwd_fn)?;
        Ok(DataKeyContent{
            private_key: signed_secret_key.to_armored_bytes(None)?,
            public_key: signed_public_key.to_armored_bytes(None)?,
            certificate: vec![],
            fingerprint: encode_u8_to_hex_string(&signed_secret_key.fingerprint()),
        })
    }

    fn sign(&self, content: Vec<u8>, options: HashMap<String, String>) -> Result<Vec<u8>> {
        let mut digest = HashAlgorithm::SHA2_256;
        if let Some(digest_str) = options.get("digest_algorithm") {
                digest = get_digest_algorithm(digest_str)?
        }
        let passwd_fn = || return match options.get("passphrase") {
            None => {
                String::new()
            }
            Some(password) => {
                password.to_string()
            }
        };
        let now = Utc::now();
        let sig_cfg = SignatureConfig {
            version: SignatureVersion::V4,
            typ: SignatureType::Binary,
            pub_alg: self.public_key.primary_key.algorithm(),
            hash_alg: digest,
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
        if let Some(detached) = options.get(options::DETACHED) {
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
