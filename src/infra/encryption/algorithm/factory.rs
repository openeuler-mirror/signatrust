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
use crate::infra::encryption::algorithm::aes::Aes256GcmEncryptor;
use crate::util::error::Result;
use std::str::FromStr;

pub struct AlgorithmFactory {}

impl AlgorithmFactory {
    pub fn new_algorithm(algo: &str) -> Result<Box<dyn Encryptor>> {
        let algorithm = Algorithm::from_str(algo)?;
        info!("encryption algorithm configured with {:?}", algorithm);
        match algorithm {
            Algorithm::Aes256GSM => Ok(Box::<Aes256GcmEncryptor>::default()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_algorithm_factory() {
        assert!(AlgorithmFactory::new_algorithm("aes-512-gcm").is_err());
        let algo = AlgorithmFactory::new_algorithm("aes256gsm")
            .expect("algorithm from valid string should succeed");
        assert_eq!(algo.algorithm(), Algorithm::Aes256GSM);
    }
}
