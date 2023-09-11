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

use hex;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use serde::{Serialize, Serializer};
use std::collections::{HashMap, BTreeMap};
use std::path::Path;
use sha2::{Sha256, Digest};
use crate::domain::datakey::entity::Visibility;
use crate::util::error::{Error, Result as LibraryResult};

pub fn encode_u8_to_hex_string(value: &[u8]) -> String {
    value
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>()
}

pub fn get_datakey_full_name(name: &str, email: &str, visibility: &Visibility) -> LibraryResult<String> {
    let names: Vec<_> = name.split(':').collect();
    if visibility.to_owned() == Visibility::Public {
        return if names.len() <= 1 {
            Ok(name.to_owned())
        } else {
            Err(Error::ParameterError("public key name should not contains ':'".to_string()))
        }
    } else {
        if names.len() <= 1 {
            return Ok(format!("{}:{}", email, name));
        } else if names.len() > 2 {
            return Err(Error::ParameterError("private key should in the format of {email}:{key_name}".to_string()))
        } else if names[0] != email {
            return Err(Error::ParameterError("private key email prefix not matched':'".to_string()))
        }
        return Ok(name.to_owned())
    }
}

pub fn decode_hex_string_to_u8(value: &String) -> Vec<u8> {
    hex::decode(value).unwrap()
}

pub fn generate_api_token() -> String {
    thread_rng().sample_iter(&Alphanumeric).take(40).map(char::from).collect()
}

pub fn generate_csrf_parent_token() -> Vec<u8> {
    let number: Vec<u8> = (0..64).map(|_| thread_rng().gen::<u8>()).collect();
    number
}
pub fn truncate_string_to_protect_key(s: &str) -> [u8; 32] {
    let truncated = &s.as_bytes()[..32].to_owned();
    let mut result = [0u8; 32];
    result[..truncated.len()].copy_from_slice(truncated);
    result
}

pub fn file_exists(file_path: &str) -> bool {
    let path = Path::new(file_path);
    path.exists()
}

pub fn get_token_hash(real_token: &str) -> String {
    let mut hasher = Sha256::default();
    hasher.update(real_token);
    let digest = hasher.finalize();
    hex::encode(digest)
}

pub fn sorted_map<S: Serializer, K: Serialize + Ord, V: Serialize>(value: &HashMap<K, V>, serializer: S) -> Result<S::Ok, S::Error> {
    let mut items: Vec<(_, _)> = value.iter().collect();
    items.sort_by(|a, b| a.0.cmp(b.0));
    BTreeMap::from_iter(items).serialize(serializer)
}

#[cfg(test)]
mod test {
    use std::env;
    use std::fs::File;
    use uuid::Uuid;
    use super::*;

    #[test]
    fn test_get_datakey_full_name() {
        let private = Visibility::Private;
        let public = Visibility::Public;
        let name_with_prefix = "fake_email@gmail.com:test_key";
        let name_with_prefix2 = "fake_email2@gmail.com:test_key";
        let name_with_prefix3 = "fake_email@gmail.com:fake3_email@gmail.com:test_key";
        let name_without_prefix = "test_key";
        //public key
        assert_eq!(get_datakey_full_name(name_without_prefix, "fake_email@gmail.com", &public).unwrap(), name_without_prefix.to_string());
        get_datakey_full_name(name_with_prefix, "fake_email@gmail.com", &public).expect_err("public key name should not contains ':'");
        assert_eq!(get_datakey_full_name(name_without_prefix, "fake_email@gmail.com", &private).unwrap(), name_with_prefix.to_string());
        assert_eq!(get_datakey_full_name(name_with_prefix, "fake_email@gmail.com", &private).unwrap(), name_with_prefix.to_string());
        get_datakey_full_name(name_with_prefix2, "fake_email@gmail.com", &private).expect_err("private key email prefix not matched':'");
        get_datakey_full_name(name_with_prefix3, "fake_email@gmail.com", &private).expect_err("private key should in the format of {email}:{key_name}");
    }

    #[test]
    fn test_generate_random_tokens() {
        let token_a = generate_api_token();
        let token_b = generate_api_token();
        let token_c = generate_api_token();
        assert_ne!(token_a, token_b);
        assert_ne!(token_b, token_c);
    }

    #[test]
    fn test_compute_token_hash_unique() {
        let token_a = generate_api_token();
        let token_b = generate_api_token();
        let hash_a = get_token_hash(&token_a);
        let hash_b = get_token_hash(&token_b);
        let hash_c = get_token_hash(&token_a);
        assert_eq!(hash_a, hash_c);
        assert_ne!(hash_a, hash_b);
        assert_eq!(hash_a.len(), hash_b.len());
    }

    #[test]
    fn test_encode_decode_hex_string_to_u8() {
        let content = "AD12FF00".to_string();
        let decoded = decode_hex_string_to_u8(&content);
        assert_eq!(decoded, vec![173, 18, 255, 00]);
        let content_a = encode_u8_to_hex_string(&decoded);
        assert_eq!(content, content_a);
    }

    #[test]
    fn test_file_exists() {
        //generate temp file
        let valid_path = env::temp_dir().join(Uuid::new_v4().to_string());
        let _valid_file = File::create(valid_path.clone()).expect("create temporary file should work");
        let invalid_path = "./invalid/file/path/should/not/exists";
        assert!(file_exists(valid_path.to_str().unwrap()));
        assert!(!file_exists(invalid_path));
    }
}