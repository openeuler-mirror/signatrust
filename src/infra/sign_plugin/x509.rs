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
use std::time::{SystemTime, Duration};

use chrono::{DateTime, Utc};
use openssl::asn1::Asn1Time;
use openssl::cms::{CmsContentInfo, CMSOptions};
use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509;
use secstr::SecVec;
use serde::Deserialize;

use validator::{Validate, ValidationError};
use crate::util::options;
use crate::util::sign::SignType;
use crate::domain::datakey::entity::{DataKey, DataKeyContent, SecDataKey};
use crate::util::error::{Error, Result};
use crate::domain::sign_plugin::SignPlugins;
use crate::util::key::encode_u8_to_hex_string;
use super::util::{validate_utc_time_not_expire, validate_utc_time, attributes_validate};

const VALID_KEY_TYPE: [&str; 2] = ["rsa", "dsa"];
const VALID_KEY_SIZE: [&str; 3] = ["2048", "3072", "4096"];
const VALID_DIGEST_ALGORITHM: [&str; 6] = ["md5", "sha1", "sha2_256","sha2_384","sha2_512","sha2_224"];

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
    #[validate(custom(function = "validate_utc_time", message="invalid x509 attribute 'create_at'"))]
    create_at: String,
    #[validate(custom(function= "validate_utc_time_not_expire", message="invalid x509 attribute 'expire_at'"))]
    expire_at: String,
}

#[derive(Debug, Validate, Deserialize)]
pub struct X509KeyImportParameter {
    key_type: String,
    #[validate(custom(function = "validate_x509_key_size", message="invalid x509 attribute 'key_length'"))]
    key_length: String,
    #[validate(custom(function= "validate_x509_digest_algorithm_type", message="invalid digest algorithm"))]
    digest_algorithm: String,
    #[validate(custom(function = "validate_utc_time", message="invalid x509 attribute 'create_at'"))]
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
            "md5" => Ok(MessageDigest::md5()),
            "sha1" => Ok(MessageDigest::sha1()),
            "sha2_256" => Ok(MessageDigest::sha224()),
            "sha2_384" => Ok(MessageDigest::sha256()),
            "sha2_512" => Ok(MessageDigest::sha384()),
            "sha2_224" => Ok(MessageDigest::sha512()),
            _ => Err(Error::ParameterError(
                "invalid digest algorithm for x509".to_string(),
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
    if !VALID_KEY_TYPE.contains(&key_type) {
        return Err(ValidationError::new("invalid key type, possible values are rsa/dsa"));
    }
    Ok(())
}

fn validate_x509_key_size(key_size: &str) -> std::result::Result<(), ValidationError> {
    if !VALID_KEY_SIZE.contains(&key_size) {
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
    if !VALID_DIGEST_ALGORITHM.contains(&key_type) {
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

impl SignPlugins for X509Plugin {
    fn new(db: SecDataKey) -> Result<Self> {
        Ok(Self {
            private_key: db.private_key.clone(),
            public_key: db.public_key.clone(),
            certificate: db.certificate.clone(),
            identity: db.identity.clone(),
            attributes: db.attributes
        })
    }

    fn validate_and_update(key: &mut DataKey) -> Result<()> where Self: Sized {
        let _ = attributes_validate::<X509KeyImportParameter>(&key.attributes)?;
        let _private_key = PKey::private_key_from_pem(&key.private_key)?;
        let certificate = x509::X509::from_pem(&key.certificate)?;
        if !key.public_key.is_empty() {
            let _public_key = PKey::public_key_from_pem(&key.public_key)?;
        }
        let unix_time = Asn1Time::from_unix(0)?.diff(certificate.not_after())?;
        let expire = SystemTime::UNIX_EPOCH + Duration::from_secs(unix_time.days as u64 * 86400 + unix_time.secs as u64);
        key.expire_at = expire.into();
        key.fingerprint = encode_u8_to_hex_string(
            certificate.digest(MessageDigest::from_name("sha1").ok_or(Error::GeneratingKeyError("unable to generate digester".to_string()))?)?.as_ref());
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
        let parameter = attributes_validate::<X509KeyGenerationParameter>(attributes)?;
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
        Ok(DataKeyContent{
            private_key: keys.private_key_to_pem_pkcs8()?,
            public_key: keys.public_key_to_pem()?,
            certificate: cert.to_pem()?,
            fingerprint: encode_u8_to_hex_string(cert.digest(
                MessageDigest::from_name("sha1").ok_or(Error::GeneratingKeyError("unable to generate digester".to_string()))?)?.as_ref())
        })
    }

    fn sign(&self, content: Vec<u8>, options: HashMap<String, String>) -> Result<Vec<u8>> {
        let private_key = PKey::private_key_from_pem(self.private_key.unsecure())?;
        let certificate = x509::X509::from_pem(self.certificate.unsecure())?;
        match SignType::from_str(options.get(options::SIGN_TYPE).unwrap_or(&SignType::Cms.to_string()))? {
            SignType::Authenticode => {
                let p7b = efi_signer::EfiImage::pem_to_p7(self.certificate.unsecure())?;
                Ok(efi_signer::EfiImage::do_sign_signature(
                    content,
                    p7b,
                    private_key.private_key_to_pem_pkcs8()?,
                    None)?.encode()?)
            }
            SignType::PKCS7 => {
                let pkcs7 = Pkcs7::sign(
                    &certificate,
                    &private_key,
                    Stack::new().as_ref()?,
                    &content,
                    Pkcs7Flags::DETACHED
                        | Pkcs7Flags::NOCERTS
                        | Pkcs7Flags::BINARY
                        | Pkcs7Flags::NOSMIMECAP
                        | Pkcs7Flags::NOATTR)?;
                Ok(pkcs7.to_der()?)
            }
            SignType::Cms => {
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
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::{Duration, Utc};
    use secstr::SecVec;
    use crate::domain::datakey::entity::{KeyState, Visibility};
    use crate::domain::datakey::entity::{KeyType};
    use crate::util::options::{SIGN_TYPE};

    fn get_default_parameter() -> HashMap<String, String> {
        HashMap::from([
            ("common_name".to_string(), "name".to_string()),
            ("organizational_unit".to_string(), "infra".to_string()),
            ("organization".to_string(), "openEuler".to_string()),
            ("locality".to_string(), "guangzhou".to_string()),
            ("province_name".to_string(), "guangzhou".to_string()),
            ("country_name".to_string(), "cn".to_string()),
            ("key_type".to_string() ,"rsa".to_string()),
            ("key_length".to_string(), "2048".to_string()),
            ("digest_algorithm".to_string(), "sha2_256".to_string()),
            ("create_at".to_string(), Utc::now().to_string()),
            ("expire_at".to_string(), (Utc::now() + Duration::days(365)).to_string()),
            ("passphrase".to_string(), "123456".to_string()),
        ])
    }

    fn get_default_datakey() -> DataKey {
        let now = Utc::now();
        DataKey {
            id: 0,
            name: "fake".to_string(),
            visibility: Visibility::Public,
            description: "fake description".to_string(),
            user: 1,
            attributes: get_default_parameter(),
            key_type: KeyType::X509,
            fingerprint: "".to_string(),
            private_key: vec![],
            public_key: vec![],
            certificate: vec![],
            create_at: now,
            expire_at: now,
            key_state: KeyState::Enabled,
            user_email: None,
            request_delete_users: None,
        }
    }

    #[test]
    fn test_key_type_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("key_type".to_string(), "invalid".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect_err("invalid key type");
        parameter.insert("key_type".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect_err("invalid empty key type");
        for key_type in VALID_KEY_TYPE {
            parameter.insert("key_type".to_string(), key_type.to_string());
            attributes_validate::<X509KeyGenerationParameter>(&parameter).expect("valid key type");
        }
    }

    #[test]
    fn test_key_size_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("key_length".to_string(),  "1024".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect_err("invalid key length");
        parameter.insert("key_length".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect_err("invalid empty key length");
        for key_length in VALID_KEY_SIZE {
            parameter.insert("key_length".to_string(), key_length.to_string());
            attributes_validate::<X509KeyGenerationParameter>(&parameter).expect("valid key length");
        }
    }

    #[test]
    fn test_digest_algorithm_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("digest_algorithm".to_string(), "1234".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect_err("invalid digest algorithm");
        parameter.insert("digest_algorithm".to_string(),"".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect_err("invalid empty digest algorithm");
        for key_length in VALID_DIGEST_ALGORITHM {
            parameter.insert("digest_algorithm".to_string(),key_length.to_string());
            attributes_validate::<X509KeyGenerationParameter>(&parameter).expect("valid digest algorithm");
        }
    }

    #[test]
    fn test_create_at_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("create_at".to_string(),"1234".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect_err("invalid create at");
        parameter.insert("create_at".to_string(),"".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect_err("invalid empty create at");
        parameter.insert("create_at".to_string(), Utc::now().to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect("valid create at");
    }

    #[test]
    fn test_expire_at_generate_parameter() {
        let mut parameter = get_default_parameter();
        parameter.insert("expire_at".to_string(),"1234".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect_err("invalid expire at");
        parameter.insert("expire_at".to_string(), "".to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect_err("invalid empty expire at");
        parameter.insert("expire_at".to_string(),(Utc::now() - Duration::days(1)).to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect_err("expire at expired");
        parameter.insert("expire_at".to_string(), (Utc::now() + Duration::minutes(1)).to_string());
        attributes_validate::<X509KeyGenerationParameter>(&parameter).expect("valid expire at");
    }

    #[test]
    fn test_generate_key_with_possible_digest_hash() {
        let mut parameter = get_default_parameter();
        //choose 4 random digest algorithm
        for hash in VALID_DIGEST_ALGORITHM {
            parameter.insert("digest_algorithm".to_string(), hash.to_string());
            X509Plugin::generate_keys(&parameter).expect(format!("generate key with digest {} successfully", hash).as_str());
        }

    }

    #[test]
    fn test_generate_key_with_possible_length() {
        for key_size in VALID_KEY_SIZE{
            let mut parameter = get_default_parameter();
            parameter.insert("key_size".to_string(), key_size.to_string());
            X509Plugin::generate_keys(&parameter).expect("generate key successfully");
        }
    }

    #[test]
    fn test_generate_key_with_possible_key_type() {
        for key_type in VALID_KEY_TYPE{
            let mut parameter = get_default_parameter();
            parameter.insert("key_type".to_string(), key_type.to_string());
            X509Plugin::generate_keys(&parameter).expect("generate key successfully");
        }
    }

    #[test]
    fn test_generate_key_with_without_passphrase() {
        let mut parameter = get_default_parameter();
        X509Plugin::generate_keys(&parameter).expect("generate key successfully");
        parameter.insert("passphrase".to_string(), "".to_string());
        X509Plugin::generate_keys(&parameter).expect("generate key successfully");
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
        let mut datakey = get_default_datakey();
        datakey.public_key = public_key.as_bytes().to_vec();
        datakey.certificate = certificate.as_bytes().to_vec();
        datakey.private_key = private_key.as_bytes().to_vec();
        X509Plugin::validate_and_update(&mut datakey).expect("validate and update should work");
        assert_eq!("2123-04-29 09:48:00 UTC", datakey.expire_at.to_string());
        assert_eq!("C9345187DFA0BFB6DCBCC4827BBEA7312E43754B", datakey.fingerprint);
    }

    #[test]
    fn test_sign_successful() {
        let content = "hello world".as_bytes();
        let mut parameter = get_default_parameter();
        parameter.insert(SIGN_TYPE.to_string(), SignType::Cms.to_string());
        let keys = X509Plugin::generate_keys(&parameter).expect("generate key successfully");
        let sec_keys = SecDataKey {
            private_key: SecVec::new(keys.private_key.clone()),
            public_key: SecVec::new(keys.public_key.clone()),
            certificate: SecVec::new(keys.certificate.clone()),
            identity: "".to_string(),
            attributes: Default::default(),
        };
        let instance = X509Plugin::new(sec_keys).expect("create x509 instance successfully");
        let _signature = instance.sign(content.to_vec(), parameter).expect("sign successfully");
    }
}
