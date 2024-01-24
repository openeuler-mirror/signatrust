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
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::cms::{CMSOptions, CmsContentInfo};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509Crl, X509Extension};
use openssl_sys::{
    X509_CRL_add0_revoked, X509_CRL_new, X509_CRL_set1_lastUpdate, X509_CRL_set1_nextUpdate,
    X509_CRL_set_issuer_name, X509_CRL_sign, X509_REVOKED_new, X509_REVOKED_set_revocationDate,
    X509_REVOKED_set_serialNumber,
};
use secstr::SecVec;
use serde::Deserialize;

use super::util::{attributes_validate, validate_utc_time, validate_utc_time_not_expire};
use crate::domain::datakey::entity::{
    DataKey, DataKeyContent, KeyType, RevokedKey, SecDataKey, SecParentDateKey,
    INFRA_CONFIG_DOMAIN_NAME,
};
use crate::domain::datakey::plugins::x509::{
    X509DigestAlgorithm, X509KeyType, X509_VALID_KEY_SIZE,
};
use crate::domain::sign_plugin::SignPlugins;
use crate::util::error::{Error, Result};
use crate::util::key::{decode_hex_string_to_u8, encode_u8_to_hex_string};
use crate::util::options;
use crate::util::sign::SignType;
#[allow(unused_imports)]
use enum_iterator::all;
use validator::{Validate, ValidationError};

#[derive(Debug, Validate, Deserialize)]
pub struct X509KeyGenerationParameter {
    #[validate(length(min = 1, max = 30, message = "invalid x509 subject 'CommonName'"))]
    common_name: String,
    #[validate(length(
        min = 1,
        max = 30,
        message = "invalid x509 subject 'OrganizationalUnit'"
    ))]
    organizational_unit: String,
    #[validate(length(min = 1, max = 30, message = "invalid x509 subject 'Organization'"))]
    organization: String,
    #[validate(length(min = 1, max = 30, message = "invalid x509 subject 'Locality'"))]
    locality: String,
    #[validate(length(
        min = 1,
        max = 30,
        message = "invalid x509 subject 'StateOrProvinceName'"
    ))]
    province_name: String,
    #[validate(length(min = 2, max = 2, message = "invalid x509 subject 'CountryName'"))]
    country_name: String,
    key_type: X509KeyType,
    #[validate(custom(
        function = "validate_x509_key_size",
        message = "invalid x509 attribute 'key_length'"
    ))]
    key_length: String,
    digest_algorithm: X509DigestAlgorithm,
    #[validate(custom(
        function = "validate_utc_time",
        message = "invalid x509 attribute 'create_at'"
    ))]
    create_at: String,
    #[validate(custom(
        function = "validate_utc_time_not_expire",
        message = "invalid x509 attribute 'expire_at'"
    ))]
    expire_at: String,
}

#[derive(Debug, Validate, Deserialize)]
pub struct X509KeyImportParameter {
    key_type: X509KeyType,
    #[validate(custom(
        function = "validate_x509_key_size",
        message = "invalid x509 attribute 'key_length'"
    ))]
    key_length: String,
    digest_algorithm: X509DigestAlgorithm,
    #[validate(custom(
        function = "validate_utc_time",
        message = "invalid x509 attribute 'create_at'"
    ))]
    create_at: String,
    #[validate(custom(
        function = "validate_utc_time_not_expire",
        message = "invalid x509 attribute 'expire_at'"
    ))]
    expire_at: String,
}

impl X509KeyGenerationParameter {
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

fn validate_x509_key_size(key_size: &str) -> std::result::Result<(), ValidationError> {
    if !X509_VALID_KEY_SIZE.contains(&key_size) {
        return Err(ValidationError::new(
            "invalid key size, possible values are 2048/3072/4096",
        ));
    }
    Ok(())
}

fn days_in_duration(time: &str) -> Result<i64> {
    let start = Utc::now();
    let end = time.parse::<DateTime<Utc>>()?;
    Ok((end - start).num_days())
}

pub struct X509Plugin {
    name: String,
    private_key: SecVec<u8>,
    public_key: SecVec<u8>,
    certificate: SecVec<u8>,
    identity: String,
    attributes: HashMap<String, String>,
    parent_key: Option<SecParentDateKey>,
}

impl X509Plugin {
    fn generate_serial_number() -> Result<BigNum> {
        let mut serial_number = BigNum::new()?;
        serial_number.rand(128, MsbOption::MAYBE_ZERO, true)?;
        Ok(serial_number)
    }

    fn generate_crl_endpoint(
        &self,
        name: &str,
        infra_config: &HashMap<String, String>,
    ) -> Result<String> {
        let domain_name =
            infra_config
                .get(INFRA_CONFIG_DOMAIN_NAME)
                .ok_or(Error::GeneratingKeyError(format!(
                    "{} is not configured",
                    INFRA_CONFIG_DOMAIN_NAME
                )))?;
        Ok(format!(
            "URI:https://{}/api/v1/keys/{}/crl",
            domain_name, name
        ))
    }

    //The openssl config for ca would be like:
    // [ v3_ca ]
    // basicConstraints        = critical, CA:TRUE, pathlen:1
    // subjectKeyIdentifier    = hash
    // authorityKeyIdentifier  = keyid:always, issuer:always
    // keyUsage                = critical, cRLSign, digitalSignature, keyCertSign
    // nsCertType = objCA
    // nsComment = "Signatrust Root CA"
    #[allow(deprecated)]
    fn generate_x509ca_keys(
        &self,
        _infra_config: &HashMap<String, String>,
    ) -> Result<DataKeyContent> {
        let parameter = attributes_validate::<X509KeyGenerationParameter>(&self.attributes)?;
        //generate self signed certificate
        let keys = parameter
            .key_type
            .get_real_key_type(parameter.key_length.parse()?)?;
        let mut generator = x509::X509Builder::new()?;
        let serial_number = X509Plugin::generate_serial_number()?;
        generator.set_subject_name(parameter.get_subject_name()?.as_ref())?;
        generator.set_issuer_name(parameter.get_subject_name()?.as_ref())?;
        generator.set_pubkey(keys.as_ref())?;
        generator.set_version(2)?;
        generator.set_serial_number(Asn1Integer::from_bn(serial_number.as_ref())?.as_ref())?;
        generator.set_not_before(
            Asn1Time::days_from_now(days_in_duration(&parameter.create_at)? as u32)?.as_ref(),
        )?;
        generator.set_not_after(
            Asn1Time::days_from_now(days_in_duration(&parameter.expire_at)? as u32)?.as_ref(),
        )?;
        //ca profile
        generator.append_extension(BasicConstraints::new().ca().pathlen(1).critical().build()?)?;
        generator.append_extension(
            SubjectKeyIdentifier::new().build(&generator.x509v3_context(None, None))?,
        )?;
        generator.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&generator.x509v3_context(None, None))?,
        )?;
        generator.append_extension(
            KeyUsage::new()
                .crl_sign()
                .digital_signature()
                .key_cert_sign()
                .critical()
                .build()?,
        )?;
        generator.append_extension(X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_COMMENT,
            "Signatrust Root CA",
        )?)?;
        generator.append_extension(X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_CERT_TYPE,
            "objCA",
        )?)?;

        generator.sign(
            keys.as_ref(),
            parameter.digest_algorithm.get_real_algorithm(),
        )?;
        let cert = generator.build();
        Ok(DataKeyContent {
            private_key: keys.private_key_to_pem_pkcs8()?,
            public_key: keys.public_key_to_pem()?,
            certificate: cert.to_pem()?,
            fingerprint: encode_u8_to_hex_string(
                cert.digest(
                    MessageDigest::from_name("sha1").ok_or(Error::GeneratingKeyError(
                        "unable to generate digester".to_string(),
                    ))?,
                )?
                .as_ref(),
            ),
            serial_number: Some(encode_u8_to_hex_string(&serial_number.to_vec())),
        })
    }

    //The openssl config for ca would be like:
    // [ v3_ica ]
    // basicConstraints        = critical, CA:TRUE, pathlen:0
    // subjectKeyIdentifier    = hash
    // authorityKeyIdentifier  = keyid:always, issuer:always
    // keyUsage                = critical, cRLSign, digitalSignature, keyCertSign
    // authorityInfoAccess     = OCSP;URI:<Signatrust OSCP Responder>, caIssuers;URI:<Signatrust CA URI>
    // nsCertType = objCA
    // nsComment = "Signatrust Intermediate CA"
    #[allow(deprecated)]
    fn generate_x509ica_keys(
        &self,
        _infra_config: &HashMap<String, String>,
    ) -> Result<DataKeyContent> {
        let parameter = attributes_validate::<X509KeyGenerationParameter>(&self.attributes)?;
        //load the ca certificate and private key
        if self.parent_key.is_none() {
            return Err(Error::GeneratingKeyError(
                "parent key is not provided".to_string(),
            ));
        }
        let ca_key =
            PKey::private_key_from_pem(self.parent_key.clone().unwrap().private_key.unsecure())?;
        let ca_cert =
            x509::X509::from_pem(self.parent_key.clone().unwrap().certificate.unsecure())?;
        //generate self signed certificate
        let keys = parameter
            .key_type
            .get_real_key_type(parameter.key_length.parse()?)?;
        let mut generator = x509::X509Builder::new()?;
        let serial_number = X509Plugin::generate_serial_number()?;
        generator.set_subject_name(parameter.get_subject_name()?.as_ref())?;
        generator.set_issuer_name(ca_cert.subject_name())?;
        generator.set_pubkey(keys.as_ref())?;
        generator.set_version(2)?;
        generator.set_serial_number(Asn1Integer::from_bn(serial_number.as_ref())?.as_ref())?;
        generator.set_not_before(
            Asn1Time::days_from_now(days_in_duration(&parameter.create_at)? as u32)?.as_ref(),
        )?;
        generator.set_not_after(
            Asn1Time::days_from_now(days_in_duration(&parameter.expire_at)? as u32)?.as_ref(),
        )?;
        //ca profile
        generator.append_extension(BasicConstraints::new().ca().pathlen(0).critical().build()?)?;
        generator.append_extension(
            SubjectKeyIdentifier::new()
                .build(&generator.x509v3_context(Some(ca_cert.as_ref()), None))?,
        )?;
        generator.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&generator.x509v3_context(Some(ca_cert.as_ref()), None))?,
        )?;
        generator.append_extension(
            KeyUsage::new()
                .crl_sign()
                .digital_signature()
                .key_cert_sign()
                .critical()
                .build()?,
        )?;
        //NOTE: sbverify for EFI file will fail, enable when fixed
        // generator.append_extension(X509Extension::new_nid(
        //     None,
        //     None,
        //     Nid::CRL_DISTRIBUTION_POINTS,
        //     &self.generate_crl_endpoint(&self.parent_key.clone().unwrap().name, infra_config)?,
        // )?)?;
        generator.append_extension(X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_COMMENT,
            "Signatrust Intermediate CA",
        )?)?;
        generator.append_extension(X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_CERT_TYPE,
            "objCA",
        )?)?;
        generator.sign(
            ca_key.as_ref(),
            parameter.digest_algorithm.get_real_algorithm(),
        )?;
        let cert = generator.build();
        //use parent private key to sign the certificate
        Ok(DataKeyContent {
            private_key: keys.private_key_to_pem_pkcs8()?,
            public_key: keys.public_key_to_pem()?,
            certificate: cert.to_pem()?,
            fingerprint: encode_u8_to_hex_string(
                cert.digest(
                    MessageDigest::from_name("sha1").ok_or(Error::GeneratingKeyError(
                        "unable to generate digester".to_string(),
                    ))?,
                )?
                .as_ref(),
            ),
            serial_number: Some(encode_u8_to_hex_string(&serial_number.to_vec())),
        })
    }

    //The openssl config for ee would be like:
    // [ v3_ee ]
    // basicConstraints        = critical, CA:FALSE
    // subjectKeyIdentifier    = hash
    // authorityKeyIdentifier  = keyid:always, issuer:always
    // keyUsage                = critical, digitalSignature, nonRepudiation
    // extendedKeyUsage        = codeSigning
    // authorityInfoAccess     = OCSP;URI:<Signatrust OSCP Responder>, caIssuers;URI:<Signatrust CA URI>
    // nsCertType = objsign
    // nsComment = "Signatrust Sign Certificate"
    #[allow(deprecated)]
    fn generate_x509ee_keys(
        &self,
        _infra_config: &HashMap<String, String>,
    ) -> Result<DataKeyContent> {
        let parameter = attributes_validate::<X509KeyGenerationParameter>(&self.attributes)?;
        //load the ca certificate and private key
        if self.parent_key.is_none() {
            return Err(Error::GeneratingKeyError(
                "parent key is not provided".to_string(),
            ));
        }
        let ca_key =
            PKey::private_key_from_pem(self.parent_key.clone().unwrap().private_key.unsecure())?;
        let ca_cert =
            x509::X509::from_pem(self.parent_key.clone().unwrap().certificate.unsecure())?;
        //generate self signed certificate
        let keys = parameter
            .key_type
            .get_real_key_type(parameter.key_length.parse()?)?;
        let mut generator = x509::X509Builder::new()?;
        let serial_number = X509Plugin::generate_serial_number()?;
        generator.set_subject_name(parameter.get_subject_name()?.as_ref())?;
        generator.set_issuer_name(ca_cert.subject_name())?;
        generator.set_pubkey(keys.as_ref())?;
        generator.set_version(2)?;
        generator.set_serial_number(Asn1Integer::from_bn(serial_number.as_ref())?.as_ref())?;
        generator.set_not_before(
            Asn1Time::days_from_now(days_in_duration(&parameter.create_at)? as u32)?.as_ref(),
        )?;
        generator.set_not_after(
            Asn1Time::days_from_now(days_in_duration(&parameter.expire_at)? as u32)?.as_ref(),
        )?;
        //ca profile
        generator.append_extension(BasicConstraints::new().critical().build()?)?;
        generator.append_extension(
            SubjectKeyIdentifier::new()
                .build(&generator.x509v3_context(Some(ca_cert.as_ref()), None))?,
        )?;
        generator.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&generator.x509v3_context(Some(ca_cert.as_ref()), None))?,
        )?;
        generator.append_extension(ExtendedKeyUsage::new().code_signing().build()?)?;
        //NOTE: then signing cert should not contain any key usage extension
        //generator.append_extension(
        //    KeyUsage::new()
        //        .crl_sign()
        //        .digital_signature()
        //        .key_cert_sign()
        //        .critical()
        //        .build()?,
        //)?;
        //NOTE: sbverify for EFI file will fail, enable when fixed
        // generator.append_extension(X509Extension::new_nid(
        //     None,
        //     None,
        //     Nid::CRL_DISTRIBUTION_POINTS,
        //     &self.generate_crl_endpoint(&self.parent_key.clone().unwrap().name, infra_config)?,
        // )?)?;
        generator.append_extension(X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_COMMENT,
            "Signatrust Sign Certificate",
        )?)?;
        generator.append_extension(X509Extension::new_nid(
            None,
            None,
            Nid::NETSCAPE_CERT_TYPE,
            "objsign",
        )?)?;
        generator.sign(
            ca_key.as_ref(),
            parameter.digest_algorithm.get_real_algorithm(),
        )?;
        let cert = generator.build();
        //use parent private key to sign the certificate
        Ok(DataKeyContent {
            private_key: keys.private_key_to_pem_pkcs8()?,
            public_key: keys.public_key_to_pem()?,
            certificate: cert.to_pem()?,
            fingerprint: encode_u8_to_hex_string(
                cert.digest(
                    MessageDigest::from_name("sha1").ok_or(Error::GeneratingKeyError(
                        "unable to generate digester".to_string(),
                    ))?,
                )?
                .as_ref(),
            ),
            serial_number: Some(encode_u8_to_hex_string(&serial_number.to_vec())),
        })
    }
}

impl SignPlugins for X509Plugin {
    fn new(db: SecDataKey) -> Result<Self> {
        let mut plugin = Self {
            name: db.name.clone(),
            private_key: db.private_key.clone(),
            public_key: db.public_key.clone(),
            certificate: db.certificate.clone(),
            identity: db.identity.clone(),
            attributes: db.attributes,
            parent_key: None,
        };
        if let Some(parent) = db.parent {
            plugin.parent_key = Some(parent);
        }
        Ok(plugin)
    }

    fn validate_and_update(key: &mut DataKey) -> Result<()>
    where
        Self: Sized,
    {
        let _ = attributes_validate::<X509KeyImportParameter>(&key.attributes)?;
        let _private_key = PKey::private_key_from_pem(&key.private_key)?;
        let certificate = x509::X509::from_pem(&key.certificate)?;
        if !key.public_key.is_empty() {
            let _public_key = PKey::public_key_from_pem(&key.public_key)?;
        }
        let unix_time = Asn1Time::from_unix(0)?.diff(certificate.not_after())?;
        let expire = SystemTime::UNIX_EPOCH
            + Duration::from_secs(unix_time.days as u64 * 86400 + unix_time.secs as u64);
        key.expire_at = expire.into();
        key.fingerprint = encode_u8_to_hex_string(
            certificate
                .digest(
                    MessageDigest::from_name("sha1").ok_or(Error::GeneratingKeyError(
                        "unable to generate digester".to_string(),
                    ))?,
                )?
                .as_ref(),
        );
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
        &self,
        key_type: &KeyType,
        infra_config: &HashMap<String, String>,
    ) -> Result<DataKeyContent> {
        match key_type {
            KeyType::X509CA => self.generate_x509ca_keys(infra_config),
            KeyType::X509ICA => self.generate_x509ica_keys(infra_config),
            KeyType::X509EE => self.generate_x509ee_keys(infra_config),
            _ => Err(Error::GeneratingKeyError(
                "x509 plugin only support x509ca, x509ica and x509ee key type".to_string(),
            )),
        }
    }

    fn sign(&self, content: Vec<u8>, options: HashMap<String, String>) -> Result<Vec<u8>> {
        let private_key = PKey::private_key_from_pem(self.private_key.unsecure())?;
        let certificate = x509::X509::from_pem(self.certificate.unsecure())?;
        let mut cert_stack = Stack::new()?;
        cert_stack.push(certificate.clone())?;
        if self.parent_key.is_some() {
            cert_stack.push(x509::X509::from_pem(
                self.parent_key.clone().unwrap().certificate.unsecure(),
            )?)?;
        }
        match SignType::from_str(
            options
                .get(options::SIGN_TYPE)
                .unwrap_or(&SignType::Cms.to_string()),
        )? {
            SignType::Authenticode => {
                let mut bufs: Vec<Vec<u8>> = vec![];
                if self.parent_key.is_some() {
                    bufs.push(
                        self.parent_key
                            .clone()
                            .unwrap()
                            .certificate
                            .unsecure()
                            .to_vec(),
                    );
                }
                bufs.push(self.certificate.unsecure().to_vec());

                let p7b = efi_signer::EfiImage::pems_to_p7(bufs)?;
                Ok(efi_signer::EfiImage::do_sign_signature(
                    content,
                    p7b,
                    private_key.private_key_to_pem_pkcs8()?,
                    None,
                    efi_signer::DigestAlgorithm::Sha256,
                )?
                .encode()?)
            }
            SignType::PKCS7 => {
                let pkcs7 = Pkcs7::sign(
                    &certificate,
                    &private_key,
                    &cert_stack,
                    &content,
                    Pkcs7Flags::DETACHED
                        | Pkcs7Flags::NOCERTS
                        | Pkcs7Flags::BINARY
                        | Pkcs7Flags::NOSMIMECAP,
                )?;
                Ok(pkcs7.to_der()?)
            }
            SignType::Cms => {
                //cms option reference: https://man.openbsd.org/CMS_sign.3
                let cms_signature = CmsContentInfo::sign(
                    Some(&certificate),
                    Some(&private_key),
                    Some(&cert_stack),
                    Some(&content),
                    CMSOptions::DETACHED
                        | CMSOptions::CMS_NOCERTS
                        | CMSOptions::BINARY
                        | CMSOptions::NOSMIMECAP,
                )?;
                Ok(cms_signature.to_der()?)
            }
        }
    }

    fn generate_crl_content(
        &self,
        revoked_keys: Vec<RevokedKey>,
        last_update: DateTime<Utc>,
        next_update: DateTime<Utc>,
    ) -> Result<Vec<u8>> {
        let parameter = attributes_validate::<X509KeyGenerationParameter>(&self.attributes)?;
        let private_key = PKey::private_key_from_pem(self.private_key.unsecure())?;
        let certificate = x509::X509::from_pem(self.certificate.unsecure())?;

        //prepare raw crl content
        let crl = unsafe { X509_CRL_new() };
        let x509_name = certificate.subject_name().as_ptr();

        unsafe {
            X509_CRL_set_issuer_name(crl, x509_name);
        };
        unsafe {
            X509_CRL_set1_lastUpdate(
                crl,
                Asn1Time::from_unix(last_update.naive_utc().timestamp())?.as_ptr(),
            )
        };
        unsafe {
            X509_CRL_set1_nextUpdate(
                crl,
                Asn1Time::from_unix(next_update.naive_utc().timestamp())?.as_ptr(),
            )
        };
        for revoked_key in revoked_keys {
            //TODO: Add revoke reason here.
            if let Some(serial_number) = revoked_key.serial_number {
                let cert_serial = BigNum::from_slice(&decode_hex_string_to_u8(&serial_number))?;
                let revoked = unsafe { X509_REVOKED_new() };
                unsafe {
                    X509_REVOKED_set_serialNumber(
                        revoked,
                        Asn1Integer::from_bn(&cert_serial)?.as_ptr(),
                    )
                };
                unsafe {
                    X509_REVOKED_set_revocationDate(
                        revoked,
                        Asn1Time::from_unix(revoked_key.create_at.naive_utc().timestamp())?
                            .as_ptr(),
                    )
                };
                unsafe { X509_CRL_add0_revoked(crl, revoked) };
            }
        }
        unsafe {
            X509_CRL_sign(
                crl,
                private_key.as_ptr(),
                parameter.digest_algorithm.get_real_algorithm().as_ptr(),
            )
        };
        let content = unsafe { X509Crl::from_ptr(crl) };
        Ok(content.to_pem()?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::domain::datakey::entity::KeyType;
    use crate::domain::datakey::entity::{KeyState, ParentKey, Visibility, X509RevokeReason};
    use crate::domain::encryption_engine::EncryptionEngine;
    use crate::infra::encryption::dummy_engine::DummyEngine;
    use chrono::{Duration, Utc};
    use secstr::SecVec;
    use std::env;

    fn get_infra_config() -> HashMap<String, String> {
        HashMap::from([(
            INFRA_CONFIG_DOMAIN_NAME.to_string(),
            "test.hostname".to_string(),
        )])
    }

    fn get_encryption_engine() -> Box<dyn EncryptionEngine> {
        Box::new(DummyEngine::default())
    }

    fn get_default_parameter() -> HashMap<String, String> {
        HashMap::from([
            ("common_name".to_string(), "name".to_string()),
            ("organizational_unit".to_string(), "infra".to_string()),
            ("organization".to_string(), "openEuler".to_string()),
            ("locality".to_string(), "guangzhou".to_string()),
            ("province_name".to_string(), "guangzhou".to_string()),
            ("country_name".to_string(), "cn".to_string()),
            ("key_type".to_string(), "rsa".to_string()),
            ("key_length".to_string(), "2048".to_string()),
            ("digest_algorithm".to_string(), "sha2_256".to_string()),
            ("create_at".to_string(), Utc::now().to_string()),
            (
                "expire_at".to_string(),
                (Utc::now() + Duration::days(365)).to_string(),
            ),
            ("passphrase".to_string(), "123456".to_string()),
        ])
    }

    fn get_default_datakey(
        name: Option<String>,
        parameter: Option<HashMap<String, String>>,
        key_type: Option<KeyType>,
    ) -> DataKey {
        let now = Utc::now();
        let mut datakey = DataKey {
            id: 0,
            name: "fake".to_string(),
            visibility: Visibility::Public,
            description: "fake description".to_string(),
            user: 1,
            attributes: get_default_parameter(),
            key_type: KeyType::X509EE,
            parent_id: None,
            fingerprint: "".to_string(),
            serial_number: None,
            private_key: vec![],
            public_key: vec![],
            certificate: vec![],
            create_at: now,
            expire_at: now,
            key_state: KeyState::Enabled,
            user_email: None,
            request_delete_users: None,
            request_revoke_users: None,
            parent_key: None,
        };
        if let Some(name) = name {
            datakey.name = name;
        }
        if let Some(parameter) = parameter {
            datakey.attributes = parameter;
        }
        if let Some(key) = key_type {
            datakey.key_type = key;
        }
        datakey
    }

    /// helper function to get a usable X509plugin
    async fn get_default_plugin() -> X509Plugin {
        let parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();
        // create ca
        let ca_key = get_default_datakey(
            Some("fake ca".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        let sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey).expect("create plugin successfully");
        let ca_content = plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect(format!("generate ca key with no passphrase successfully").as_str());

        // create ica
        let mut ica_key = get_default_datakey(
            Some("fake ica".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        ica_key.parent_key = Some(ParentKey {
            name: "fake ca".to_string(),
            private_key: ca_content.private_key,
            public_key: ca_content.public_key,
            certificate: ca_content.certificate,
            attributes: ca_key.attributes.clone(),
        });
        let sec_datakey = SecDataKey::load(&ica_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey).expect("create plugin successfully");
        let ica_content = plugin
            .generate_keys(&KeyType::X509ICA, &infra_config)
            .expect(format!("generate ica key with no passphrase successfully").as_str());

        //create ee
        let mut ee_key = get_default_datakey(
            Some("fake ee".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        ee_key.parent_key = Some(ParentKey {
            name: "fake ca".to_string(),
            private_key: ica_content.private_key,
            public_key: ica_content.public_key,
            certificate: ica_content.certificate,
            attributes: ica_key.attributes.clone(),
        });
        let sec_datakey = SecDataKey::load(&ica_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey).expect("create plugin successfully");
        let ee_content = plugin
            .generate_keys(&KeyType::X509EE, &infra_config)
            .expect(format!("generate ee key with no passphrase successfully").as_str());

        let sec_keys = SecDataKey {
            name: "".to_string(),
            private_key: SecVec::new(ee_content.private_key.clone()),
            public_key: SecVec::new(ee_content.public_key.clone()),
            certificate: SecVec::new(ee_content.certificate.clone()),
            identity: "".to_string(),
            attributes: Default::default(),
            parent: None,
        };
        X509Plugin::new(sec_keys).expect("create x509 instance successfully")
    }

    #[test]
    fn test_key_type_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("key_type".to_string(), "invalid".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid key type");
        parameter.insert("key_type".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid empty key type");
        for key_type in all::<X509KeyType>().collect::<Vec<_>>() {
            parameter.insert("key_type".to_string(), key_type.to_string());
            attributes_validate::<X509KeyGenerationParameter>(&parameter).expect("valid key type");
        }
    }

    #[test]
    fn test_key_size_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("key_length".to_string(), "1024".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid key length");
        parameter.insert("key_length".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid empty key length");
        for key_length in X509_VALID_KEY_SIZE {
            parameter.insert("key_length".to_string(), key_length.to_string());
            attributes_validate::<X509KeyGenerationParameter>(&parameter)
                .expect("valid key length");
        }
    }

    #[test]
    fn test_digest_algorithm_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("digest_algorithm".to_string(), "1234".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid digest algorithm");
        parameter.insert("digest_algorithm".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid empty digest algorithm");
        for key_length in all::<X509DigestAlgorithm>().collect::<Vec<_>>() {
            parameter.insert("digest_algorithm".to_string(), key_length.to_string());
            attributes_validate::<X509KeyGenerationParameter>(&parameter)
                .expect("valid digest algorithm");
        }
    }

    #[test]
    fn test_create_at_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("create_at".to_string(), "1234".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid create at");
        parameter.insert("create_at".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid empty create at");
        parameter.insert("create_at".to_string(), Utc::now().to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect("valid create at");
    }

    #[test]
    fn test_expire_at_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("expire_at".to_string(), "1234".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid expire at");
        parameter.insert("expire_at".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("invalid empty expire at");
        parameter.insert(
            "expire_at".to_string(),
            (Utc::now() - Duration::days(1)).to_string(),
        );
        attributes_validate::<X509KeyGenerationParameter>(&parameter)
            .expect_err("expire at expired");
        parameter.insert(
            "expire_at".to_string(),
            (Utc::now() + Duration::minutes(1)).to_string(),
        );
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect("valid expire at");
    }

    #[tokio::test]
    async fn test_generate_ca_with_possible_digest_hash() {
        let mut parameter = get_default_parameter();
        //choose 4 random digest algorithm
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();
        for hash in all::<X509DigestAlgorithm>().collect::<Vec<_>>() {
            parameter.insert("digest_algorithm".to_string(), hash.to_string());
            let sec_datakey = SecDataKey::load(
                &get_default_datakey(None, Some(parameter.clone()), Some(KeyType::X509CA)),
                &dummy_engine,
            )
            .await
            .expect("load sec datakey successfully");
            let plugin = X509Plugin::new(sec_datakey).expect("create plugin successfully");
            plugin
                .generate_keys(&KeyType::X509CA, &infra_config)
                .expect(format!("generate ca key with digest {} successfully", hash).as_str());
        }
    }

    #[tokio::test]
    async fn test_generate_key_with_possible_length() {
        let mut parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();
        for key_size in X509_VALID_KEY_SIZE {
            parameter.insert("key_size".to_string(), key_size.to_string());
            let sec_datakey = SecDataKey::load(
                &get_default_datakey(None, Some(parameter.clone()), Some(KeyType::X509CA)),
                &dummy_engine,
            )
            .await
            .expect("load sec datakey successfully");
            let plugin = X509Plugin::new(sec_datakey).expect("create plugin successfully");
            plugin
                .generate_keys(&KeyType::X509CA, &infra_config)
                .expect(
                    format!("generate ca key with key size {} successfully", key_size).as_str(),
                );
        }
    }

    #[tokio::test]
    async fn test_generate_key_with_possible_key_type() {
        let mut parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();
        for key_type in all::<X509KeyType>().collect::<Vec<_>>() {
            parameter.insert("key_type".to_string(), key_type.to_string());
            let sec_datakey = SecDataKey::load(
                &get_default_datakey(None, Some(parameter.clone()), Some(KeyType::X509CA)),
                &dummy_engine,
            )
            .await
            .expect("load sec datakey successfully");
            let plugin = X509Plugin::new(sec_datakey).expect("create plugin successfully");
            plugin
                .generate_keys(&KeyType::X509CA, &infra_config)
                .expect(
                    format!("generate ca key with key type {} successfully", key_type).as_str(),
                );
        }
    }

    #[tokio::test]
    async fn test_generate_key_with_without_passphrase() {
        let mut parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();

        let sec_datakey = SecDataKey::load(
            &get_default_datakey(None, Some(parameter.clone()), Some(KeyType::X509CA)),
            &dummy_engine,
        )
        .await
        .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey).expect("create plugin successfully");
        plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect(format!("generate ca key with no passphrase successfully").as_str());

        parameter.insert("passphrase".to_string(), "".to_string());
        let sec_datakey = SecDataKey::load(
            &get_default_datakey(None, Some(parameter.clone()), Some(KeyType::X509CA)),
            &dummy_engine,
        )
        .await
        .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey).expect("create plugin successfully");
        plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect(format!("generate ca key with passphrase successfully").as_str());
    }

    #[test]
    fn test_validate_and_update() {
        let public_key = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApj/qRL4umbfjJx1TbuXA
eOdLzVqARnGQgiwoVN+0Sas8xdco1d4Dz4UbMdDmXY5z2+50uwpmyRskcKb1fgvF
C8DUD8+ZHxEDITHQ1wqHdeEBh/D64JlD6MoAFHHlEMNEYgaYDUEJZIYp3uX4gMvg
WLsBuWDvyoSkI3j+rMcRN0NWsf7aKbA9OTKyvE5lZC6+z6fyftq4Z9gwiNENEktO
+8WAL31x1X/AHWiFwlguZlKdtozgRIkPYLU27Cz8aAvuuWGTrUYJ98UN80Wzu2gI
rnH3ztPU6gatSvVWHonDEbdjQ/kCRlE2GPZkdPyRvb4gv5BQTeDZeahoSV17Pagg
0QIDAQAB
-----END PUBLIC KEY-----";
        let certificate = "-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUDiehlVNb4SRwVz13zBnKAjuljmAwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJWU9VUl9OQU1FMCAXDTIzMDUyMzA5NDgwMFoYDzIxMjMw
NDI5MDk0ODAwWjAUMRIwEAYDVQQDDAlZT1VSX05BTUUwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCmP+pEvi6Zt+MnHVNu5cB450vNWoBGcZCCLChU37RJ
qzzF1yjV3gPPhRsx0OZdjnPb7nS7CmbJGyRwpvV+C8ULwNQPz5kfEQMhMdDXCod1
4QGH8PrgmUPoygAUceUQw0RiBpgNQQlkhine5fiAy+BYuwG5YO/KhKQjeP6sxxE3
Q1ax/topsD05MrK8TmVkLr7Pp/J+2rhn2DCI0Q0SS077xYAvfXHVf8AdaIXCWC5m
Up22jOBEiQ9gtTbsLPxoC+65YZOtRgn3xQ3zRbO7aAiucffO09TqBq1K9VYeicMR
t2ND+QJGUTYY9mR0/JG9viC/kFBN4Nl5qGhJXXs9qCDRAgMBAAGjUzBRMB0GA1Ud
DgQWBBS8CurcB1Q9kg/KXWONMNkspM3/HjAfBgNVHSMEGDAWgBS8CurcB1Q9kg/K
XWONMNkspM3/HjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAe
6+KLTWtOlsy/U5alR+g3umo7K8X/9oMAqjzrBenOgcLUKQdsbD7RzXdZ+nZBT/ZV
fzL6WNFYGq1SrcusrRdr5XG6+SXrUa88r/nw5WaeEa2lrk0s4fOr7svg6pKeR84A
M/aF+RfEhNp4l+6eKjerghTbDccOoj4kKCjST6ckTxnAiQQMZL8hXPpXURLbX2Ci
MBtYxIpT5eLClRYIREJFq/qFpAffddlVw7bENQJNoArhIUl5XxsxFz/0nVGDyM5y
vM0L0x9sI6JA4zYrfVfvwB7cvpqw4qK5dlqHtK/Np8WvLUiNDCZUondEOf1jBT3b
67xBfexCBpVVLNLP70Ql
-----END CERTIFICATE-----";
        let private_key = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCmP+pEvi6Zt+Mn
HVNu5cB450vNWoBGcZCCLChU37RJqzzF1yjV3gPPhRsx0OZdjnPb7nS7CmbJGyRw
pvV+C8ULwNQPz5kfEQMhMdDXCod14QGH8PrgmUPoygAUceUQw0RiBpgNQQlkhine
5fiAy+BYuwG5YO/KhKQjeP6sxxE3Q1ax/topsD05MrK8TmVkLr7Pp/J+2rhn2DCI
0Q0SS077xYAvfXHVf8AdaIXCWC5mUp22jOBEiQ9gtTbsLPxoC+65YZOtRgn3xQ3z
RbO7aAiucffO09TqBq1K9VYeicMRt2ND+QJGUTYY9mR0/JG9viC/kFBN4Nl5qGhJ
XXs9qCDRAgMBAAECggEAOOgN56P1zZZdQclPAtnQDVKW5t8Ao5xB69zznUHJs6HS
tqHUj4hkY4dbbKzl/cZCMFkqSc/gqRwKWCk+RPwAYeqKbDMSZcjr+lPT+ZfYEGiJ
np/FMFYmIavrZRQrZZaBdNBvAbJuZaNq96peaq/exmCU0YC18+t9R8sl2bx2TyTH
MCyDA7w/HT4BARjzYsjqXEQQzElajcVyX0VwgEtOr40HEpNQioQi8iw94FYgh4C9
awyR6ldIX5TmeFwWyfQxYR/WfXIw7ja9lXqKJ6dkBtY3x+3Z4qbCNB0rgfTY4RoX
1DVHbZNb2kxKSF7d9I8ti0GhfFxOGguS14IeVI2YQQKBgQDa3130/w7adouVJlBM
PJ1Hd5ZT1PXbymvIMuVHjE1BjfzCu9NW+voofCjQlbBejEokUwE8sY8iuU7UosZ2
IkRUwLbF0eIBqe+oXf6CbXZjx+T1n52k+SHbn2WasHndvXEXGRubwwsLo+E3WI2A
KC3Qbmj78GGErB5J+vy2tI79qQKBgQDCc2DCShQHsF6rwKCeeEHhAODMrunW0PtW
lQe4uPK1mwYMXmCLGgJXI3RzyjTLWSgzI/WTIXvrRk45gnEFiTkwt5JxxbNc2WFd
RdnQp/Qis4O/Hac2IcBqy2s4BabgEacvJNaUkoLfHAMmge2n1oeDm5/xgVgXpK1/
Aiu0ct5y6QKBgAgBVXFphsSMw2wwG42+Rc5gXFoyls90Jt8KpYIpaoX0SINi1UcA
JPgoGmIOp4W9wdR0SL5MjDyr5Gs4jOOzOyaSadzwYUDIU2CoF2/zyvm5TPGC5gQr
rIZY3SF8ROjMTf+XRoA68QN6+fjJP1upnItcDnDwiNCObwkrqeSQ1A4JAoGAM2dm
49XLd8DjNgpFK79kwwOFafavcI9schYRpX6XAvVJYwmsAfnNNpXz2gxRapRWMTbH
W67VYHwEf+WA1VLSYJOWzibSZLA+sfaePy+3NVk5cdN3+bJweIrv/C5aUA+6n5bg
dwRIPozcNFjSp7TpvBvu61wjGpT5HINJZHmdXskCgYEAjQf6bFXPMJHELD27RqiD
UDWzemeq/e6D6NJhaESg49Da0N7rsqM+UtBpM/T4Ce9zuPZhLlXJobqmzIYqVDu0
aIVg7wz2RwVCsux1duEoO8ScQghohmzn+7jysGIlN+csOClwSBaLHAIN/PmChZug
X5BboR/QJakEK+H+EUQAiDs=
-----END PRIVATE KEY-----";
        let mut datakey = get_default_datakey(None, None, None);
        datakey.public_key = public_key.as_bytes().to_vec();
        datakey.certificate = certificate.as_bytes().to_vec();
        datakey.private_key = private_key.as_bytes().to_vec();
        X509Plugin::validate_and_update(&mut datakey).expect("validate and update should work");
        assert_eq!("2123-04-29 09:48:00 UTC", datakey.expire_at.to_string());
        assert_eq!(
            "C9345187DFA0BFB6DCBCC4827BBEA7312E43754B",
            datakey.fingerprint
        );
    }

    #[tokio::test]
    async fn test_sign_whole_process_successful() {
        let parameter = get_default_parameter();
        let content = "hello world".as_bytes();
        let instance = get_default_plugin().await;
        let _signature = instance
            .sign(content.to_vec(), parameter)
            .expect("sign successfully");
    }

    #[tokio::test]
    async fn test_crl_generation() {
        let parameter = get_default_parameter();
        let dummy_engine = get_encryption_engine();
        let infra_config = get_infra_config();
        // create ca
        let mut ca_key = get_default_datakey(
            Some("fake ca".to_string()),
            Some(parameter.clone()),
            Some(KeyType::X509CA),
        );
        let sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(sec_datakey).expect("create plugin successfully");
        let ca_content = plugin
            .generate_keys(&KeyType::X509CA, &infra_config)
            .expect(format!("generate ca key with no passphrase successfully").as_str());
        ca_key.private_key = ca_content.private_key;
        ca_key.public_key = ca_content.public_key;
        ca_key.certificate = ca_content.certificate;
        ca_key.serial_number = ca_content.serial_number;
        ca_key.fingerprint = ca_content.fingerprint;
        let crl_sec_datakey = SecDataKey::load(&ca_key, &dummy_engine)
            .await
            .expect("load sec datakey successfully");
        let plugin = X509Plugin::new(crl_sec_datakey).expect("create plugin successfully");
        let revoke_time = Utc::now();
        let last_update = Utc::now() + Duration::days(1);
        let next_update = Utc::now() + Duration::days(2);
        let serial_number =
            X509Plugin::generate_serial_number().expect("generate serial number successfully");
        let revoked_keys = RevokedKey {
            id: 0,
            key_id: 0,
            ca_id: 0,
            reason: X509RevokeReason::Unspecified,
            create_at: revoke_time.clone(),
            serial_number: Some(encode_u8_to_hex_string(&serial_number.to_vec())),
        };
        //generate crl
        let content = plugin
            .generate_crl_content(vec![revoked_keys], last_update.clone(), next_update.clone())
            .expect("generate crl successfully");
        let crl = X509Crl::from_pem(&content).expect("load generated crl successfully");
        assert_eq!(
            crl.last_update()
                == Asn1Time::from_unix(last_update.naive_utc().timestamp())
                    .expect("convert to asn1 time successfully"),
            true
        );
        assert_eq!(
            crl.next_update().expect("next update is set")
                == Asn1Time::from_unix(next_update.naive_utc().timestamp())
                    .expect("convert to asn1 time successfully"),
            true
        );
        assert_eq!(crl.get_revoked().is_some(), true);
        let revoked = crl
            .get_revoked()
            .expect("revoke stack is not empty")
            .get(0)
            .expect("first revoke is not empty");
        assert_eq!(
            revoked
                .serial_number()
                .to_owned()
                .expect("convert to asn1 number work")
                == Asn1Integer::from_bn(&serial_number)
                    .expect("convert from bn number should work"),
            true
        );
        assert_eq!(
            revoked.revocation_date().to_owned()
                == Asn1Time::from_unix(revoke_time.naive_utc().timestamp())
                    .expect("convert to asn1 time successfully"),
            true
        );
    }

    #[tokio::test]
    async fn test_sign_authenticode() {
        let instance = get_default_plugin().await;

        let current_dir = env::current_dir().expect("get current dir failed");
        let efi_file = tokio::fs::read(current_dir.join("test_assets").join("shimx64.efi"))
            .await
            .unwrap();

        let file_hash = efi_signer::EfiImage::parse(&efi_file)
            .unwrap()
            .compute_digest(efi_signer::DigestAlgorithm::Sha256)
            .unwrap();
        let mut opts = HashMap::new();

        opts.insert(
            options::SIGN_TYPE.to_string(),
            SignType::Authenticode.to_string(),
        );
        instance.sign(file_hash, opts).unwrap();
    }
}
