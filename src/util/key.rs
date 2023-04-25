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
use sha2::{Sha256, Digest};

pub fn encode_u8_to_hex_string(value: &[u8]) -> String {
    value
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>()
}

pub fn decode_hex_string_to_u8(value: &String) -> Vec<u8> {
    hex::decode(value).unwrap()
}

pub fn generate_api_token() -> String {
    thread_rng().sample_iter(&Alphanumeric).take(40).map(char::from).collect()
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