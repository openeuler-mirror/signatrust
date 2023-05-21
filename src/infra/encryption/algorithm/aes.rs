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

use crate::domain::encryptor::{Algorithm, Encryptor};
use crate::util::error::Error;
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng},
    Aes256GcmSiv,
};
use generic_array::GenericArray;
use rand::{thread_rng, Rng};
use crate::util::error::Result;

pub const NONCE_LENGTH: usize = 12;
pub const KEY_LENGTH: usize = 32;

#[derive(Default)]
pub struct Aes256GcmEncryptor {}

impl Aes256GcmEncryptor {
    fn generate_nonce_bytes(&self) -> [u8; NONCE_LENGTH] {
        thread_rng().gen::<[u8; NONCE_LENGTH]>()
    }
}

impl Encryptor for Aes256GcmEncryptor {
    fn generate_key(&self) -> Vec<u8> {
        Aes256GcmSiv::generate_key(&mut OsRng).as_slice().to_vec()
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Aes256GSM
    }

    fn encrypt(&self, key: Vec<u8>, content: Vec<u8>) -> Result<Vec<u8>> {
        if key.len() != KEY_LENGTH {
            return Err(Error::EncodeError("key size not matched".to_string()))
        }
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key));
        let random = self.generate_nonce_bytes();
        let nonce = GenericArray::from_slice(&random);
        let encrypt_msg = cipher
            .encrypt(nonce, content.as_slice())
            .map_err(|e| Error::EncodeError(e.to_string()))?;
        let mut encrypted = Vec::new();
        encrypted.extend_from_slice(&random);
        encrypted.extend(encrypt_msg);
        Ok(encrypted)
    }

    fn decrypt(&self, key: Vec<u8>, content: Vec<u8>) -> Result<Vec<u8>> {
        if content.len() <= NONCE_LENGTH {
            return Err(Error::EncodeError(
                "failed to decode due to incorrect length".to_string(),
            ));
        }
        if key.len() != KEY_LENGTH {
            return Err(Error::EncodeError("key size not matched".to_string()))
        }
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key));
        let nonce = GenericArray::from_slice(&content[..NONCE_LENGTH]);
        let decrypted = cipher
            .decrypt(nonce, &content[NONCE_LENGTH..])
            .map_err(|e| Error::EncodeError(e.to_string()))?;
        Ok(decrypted)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_generate_keys() {
        let aes = Aes256GcmEncryptor::default();
        let key_1 = aes.generate_key();
        let key_2 = aes.generate_key();
        assert_ne!(key_1, key_2);
        assert_eq!(32, key_2.len());
        assert_eq!(32, key_1.len());
    }

    #[test]
    fn test_generate_nonce() {
        let aes = Aes256GcmEncryptor::default();
        let nonce_1 = aes.generate_nonce_bytes();
        let nonce_2 = aes.generate_nonce_bytes();
        assert_ne!(nonce_1, nonce_2);
        assert_eq!(NONCE_LENGTH, nonce_1.len());
        assert_eq!(NONCE_LENGTH, nonce_2.len());
    }

    #[test]
    fn test_encrypt_decrypt_successful_with_one_key() {
        let aes = Aes256GcmEncryptor::default();
        let key1 = aes.generate_key();
        let content = "fake_content".as_bytes();
        let encoded_1 = aes.encrypt(key1.clone(), content.to_vec()).expect("encode should be successful");
        let encoded_2 = aes.encrypt(key1.clone(), content.to_vec()).expect("encode should be successful");
        assert_ne!(encoded_1, encoded_2);
        assert_eq!(encoded_1.len(), encoded_1.len());
        assert_ne!(encoded_1, content);
        assert_ne!(encoded_2, content);
        let decode_1 = aes.decrypt(key1.clone(), encoded_1).expect("decode should be successful");
        let decode_2 = aes.decrypt(key1.clone(), encoded_2).expect("decode should be successful");
        assert_eq!(content, decode_1);
        assert_eq!(content, decode_2);
    }

    #[test]
    fn test_encrypt_decrypt_successful_with_different_keys() {
        let aes = Aes256GcmEncryptor::default();
        let key1 = aes.generate_key();
        let key2 = aes.generate_key();
        let content = "fake_content".as_bytes();
        let encoded_1 = aes.encrypt(key1.clone(), content.to_vec()).expect("encode should be successful");
        let encoded_2 = aes.encrypt(key2.clone(), content.to_vec()).expect("encode should be successful");
        assert_ne!(encoded_1, encoded_2);
        assert_eq!(encoded_1.len(), encoded_1.len());
        assert_ne!(encoded_1, content);
        assert_ne!(encoded_2, content);
        let decode_1 = aes.decrypt(key1.clone(), encoded_1).expect("decode should be successful");
        let decode_2 = aes.decrypt(key2.clone(), encoded_2).expect("decode should be successful");
        assert_eq!(content, decode_1);
        assert_eq!(content, decode_2);
    }

    #[test]
    fn test_encrypt_decrypt_different_content_successful_one_key() {
        let aes = Aes256GcmEncryptor::default();
        let key1 = aes.generate_key();
        let content_1 = "fake_content1".as_bytes();
        let content_2 = "fake_content 2".as_bytes();
        let encoded_1 = aes.encrypt(key1.clone(), content_1.to_vec()).expect("encode should be successful");
        let encoded_2 = aes.encrypt(key1.clone(), content_2.to_vec()).expect("encode should be successful");
        assert_ne!(encoded_1, encoded_2);
        assert_ne!(encoded_1, content_1);
        assert_ne!(encoded_2, content_2);
        let decode_1 = aes.decrypt(key1.clone(), encoded_1).expect("decode should be successful");
        let decode_2 = aes.decrypt(key1.clone(), encoded_2).expect("decode should be successful");
        assert_eq!(content_1, decode_1);
        assert_eq!(content_2, decode_2);
    }

    #[test]
    fn test_decrypt_with_invalid_content() {
        let aes = Aes256GcmEncryptor::default();
        let key1 = aes.generate_key();
        let encoded = "123456789abc".as_bytes();
        let invalid = "invalid_encoded_content_although_long_enough".as_bytes();
        let _ = aes.decrypt(key1.clone(), vec![]).expect_err("decode should fail due to content not long enough");
        let _ = aes.decrypt(key1.clone(), encoded.to_vec()).expect_err("decode should fail due to content not long enough");
        let _ = aes.decrypt(key1.clone(), invalid.to_vec()).expect_err("decode should fail due to content invalid");
    }

    #[test]
    fn test_encrypt_decrypt_with_invalid_key_size() {
        let aes = Aes256GcmEncryptor::default();
        let invalid_key = "invalid_key".as_bytes();
        let _ = aes.encrypt(invalid_key.to_vec(), vec![]).expect_err("encode should fail due to key size invalid");
        let _ = aes.decrypt(invalid_key.to_vec(), vec![]).expect_err("decode should fail due to key size invalid");
    }
}