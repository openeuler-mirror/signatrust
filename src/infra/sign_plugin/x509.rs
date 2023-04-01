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

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use openssl::asn1::Asn1Time;
use openssl::cms::{CmsContentInfo, CMSOptions};
use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509;
use secstr::SecVec;
use serde::Deserialize;

use validator::{Validate, ValidationError};
use crate::domain::datakey::entity::SecDataKey;
use crate::util::error::{Error, Result};
use crate::domain::sign_plugin::SignPlugins;
use super::util::{validate_utc_time_not_expire, validate_utc_time};

#[derive(Debug, Validate, Deserialize)]
pub struct X509KeyGenerationParameter {
    #[validate(length(min = 1, max = 30, message="invalid x509 subject 'CommonName'"))]
    common_name: String,
    #[validate(length(min = 1, max = 30, message="invalid x509 subject 'OrganizationalUnit'"))]
    organizational_unit: String,
    #[validate(length(min = 1, max = 30, message="invalid x509 subject 'Organization'"))]
    organization: String,
    #[validate(length(min = 1, max = 30, message="invalid x509 subject 'Locality'"))]
    locality: String,
    #[validate(length(min = 1, max = 30, message="invalid x509 subject 'StateOrProvinceName'"))]
    province_name: String,
    #[validate(length(min = 2, max = 2, message="invalid x509 subject 'CountryName'"))]
    country_name: String,
    #[validate(custom(function = "validate_x509_key_type", message="invalid x509 attribute 'key_type'"))]
    key_type: String,
    #[validate(custom(function = "validate_x509_key_size", message="invalid x509 attribute 'key_length'"))]
    key_length: String,
    #[validate(custom(function= "validate_x509_digest_algorithm_type", message="invalid digest algorithm"))]
    digest_algorithm: String,
    #[validate(custom(function = "validate_utc_time", message="invalid x509 attribute 'created_at'"))]
    create_at: String,
    #[validate(custom(function= "validate_utc_time_not_expire", message="invalid x509 attribute 'expire_at'"))]
    expire_at: String,
}

impl X509KeyGenerationParameter {
    pub fn get_key(&self) -> Result<PKey<Private>> {
        return match self.key_type.as_str() {
            "rsa" => Ok(PKey::from_rsa(Rsa::generate(self.key_length.parse()?)?)?),
            "dsa" => Ok(PKey::from_dsa(Dsa::generate(self.key_length.parse()?)?)?),
            _ => Err(Error::ParameterError(
                "invalid key type for x509".to_string(),
            )),
        };
    }

    pub fn get_digest_algorithm(&self) -> Result<MessageDigest> {
        return match self.digest_algorithm.as_str() {
            "none" => Ok(MessageDigest::null()),
            "md5" => Ok(MessageDigest::md5()),
            "sha1" => Ok(MessageDigest::sha1()),
            "sha2_256" => Ok(MessageDigest::sha224()),
            "sha2_384" => Ok(MessageDigest::sha256()),
            "sha2_512" => Ok(MessageDigest::sha384()),
            "sha2_224" => Ok(MessageDigest::sha512()),
            _ => Err(Error::ParameterError(
                "invalid digest algorithm for openpgp".to_string(),
            )),
        };
    }

    pub fn get_subject_name(&self) -> Result<x509::X509Name> {
        let mut x509_name = x509::X509NameBuilder::new()?;
        x509_name.append_entry_by_text("CN", &self.common_name)?;
        x509_name.append_entry_by_text("OU", &self.organizational_unit)?;
        x509_name.append_entry_by_text("O", &self.organization)?;
        x509_name.append_entry_by_text("L", &self.locality)?;
        x509_name.append_entry_by_text("ST", &self.province_name)?;
        x509_name.append_entry_by_text("C", &self.country_name)?;
        Ok(x509_name.build())
    }
}

fn validate_x509_key_type(key_type: &str) -> std::result::Result<(), ValidationError> {
    if !vec!["rsa", "dsa"].contains(&key_type) {
        return Err(ValidationError::new("invalid key type, possible values are rsa/dsa"));
    }
    Ok(())
}

fn validate_x509_key_size(key_size: &str) -> std::result::Result<(), ValidationError> {
    if !vec!["2048", "3072", "4096"].contains(&key_size) {
        return Err(ValidationError::new("invalid key size, possible values are 2048/3072/4096"));
    }
    Ok(())
}

fn days_in_duration(time: &str) -> Result<i64> {
    let start = Utc::now();
    let end = time.parse::<DateTime<Utc>>()?;
    Ok((end - start).num_days())
}

fn validate_x509_digest_algorithm_type(key_type: &str) -> std::result::Result<(), ValidationError> {
    if !vec!["none", "md5", "sha1", "sha1", "sha2_256","sha2_384","sha2_512","sha2_224"].contains(&key_type) {
        return Err(ValidationError::new("invalid hash algorithm, possible values are none/md5/sha1/sha1/sha2_256/sha2_384/sha2_512/sha2_224"));
    }
    Ok(())
}

pub struct X509Plugin {
    private_key: SecVec<u8>,
    public_key: SecVec<u8>,
    certificate: SecVec<u8>,
    identity: String,
    attributes: HashMap<String, String>
}

impl X509Plugin {
    pub fn attributes_validate(attr: &HashMap<String, String>) -> Result<X509KeyGenerationParameter> {
        let parameter: X509KeyGenerationParameter =
            serde_json::from_str(serde_json::to_string(&attr)?.as_str())?;
        match parameter.validate() {
            Ok(_) => Ok(parameter),
            Err(e) => Err(Error::ParameterError(format!("{:?}", e))),
        }
    }
}

impl SignPlugins for X509Plugin {
    fn new(db: SecDataKey) -> Result<Self> {
        Ok(Self {
            private_key: db.private_key.clone(),
            public_key: db.public_key.clone(),
            certificate: db.certificate.clone(),
            identity: db.identity.clone(),
            attributes: db.attributes.clone()
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
        attributes: &HashMap<String, String>,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let parameter = X509Plugin::attributes_validate(attributes)?;
        let keys = parameter.get_key()?;
        let mut generator = x509::X509Builder::new()?;
        generator.set_subject_name(parameter.get_subject_name()?.as_ref())?;
        generator.set_issuer_name(parameter.get_subject_name()?.as_ref())?;
        generator.set_pubkey(keys.as_ref())?;
        generator.set_version(2)?;
        generator.set_not_before(Asn1Time::days_from_now(days_in_duration(&parameter.create_at)? as u32)?.as_ref())?;
        generator.set_not_after(Asn1Time::days_from_now(days_in_duration(&parameter.expire_at)? as u32)?.as_ref())?;
        generator.sign(keys.as_ref(), parameter.get_digest_algorithm()?)?;
        let cert = generator.build();
        Ok((
            keys.private_key_to_pem_pkcs8()?,
            keys.public_key_to_pem()?,
            cert.to_pem()?
        ))
    }

    fn sign(&self, content: Vec<u8>, _options: HashMap<String, String>) -> Result<Vec<u8>> {
        let private_key = PKey::private_key_from_pem(self.private_key.unsecure())?;
        let certificate = x509::X509::from_pem(self.certificate.unsecure())?;
        //cms option reference: https://man.openbsd.org/CMS_sign.3
        let cms_signature = CmsContentInfo::sign(
            Some(&certificate),
            Some(&private_key),
            None,
            Some(&content),
            CMSOptions::DETACHED
                | CMSOptions::CMS_NOCERTS
                | CMSOptions::BINARY
                | CMSOptions::NOSMIMECAP
                | CMSOptions::NOATTR,
        )?;
        Ok(cms_signature.to_der()?)
    }
}
