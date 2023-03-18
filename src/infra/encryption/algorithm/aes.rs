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

pub const NONCE_LENGTH: usize = 12;

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

    fn encrypt(&self, key: Vec<u8>, content: Vec<u8>) -> crate::util::error::Result<Vec<u8>> {
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

    fn decrypt(&self, key: Vec<u8>, content: Vec<u8>) -> crate::util::error::Result<Vec<u8>> {
        if key.len() <= NONCE_LENGTH {
            return Err(Error::EncodeError(
                "failed to decode cluster key due to incorrect length".to_string(),
            ));
        }
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key));
        let nonce = GenericArray::from_slice(&content[..NONCE_LENGTH]);
        let decrypted = cipher
            .decrypt(nonce, &content[NONCE_LENGTH..])
            .map_err(|e| Error::EncodeError(e.to_string()))?;
        Ok(decrypted)
    }
}
