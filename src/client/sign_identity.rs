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

use std::path::PathBuf;

use crate::util::error::Result;
use crate::util::sign::{FileType, KeyType};
use std::cell::RefCell;
use std::collections::HashMap;

pub struct SignIdentity {
    //absolute file path
    pub file_path: PathBuf,
    pub key_type: KeyType,
    pub file_type: FileType,
    pub key_id: String,
    pub raw_content: Box<RefCell<Vec<Vec<u8>>>>,
    pub signature: Box<RefCell<Vec<Vec<u8>>>>,
    pub sign_options: RefCell<HashMap<String, String>>,
    pub error: RefCell<Result<()>>,
}

impl SignIdentity {
    pub(crate) fn new(
        file_type: FileType,
        file_path: PathBuf,
        key_type: KeyType,
        key_id: String,
        sign_options: HashMap<String, String>,
    ) -> Self {
        Self {
            file_type,
            file_path,
            key_type,
            key_id,
            raw_content: Box::new(RefCell::new(vec![])),
            signature: Box::new(RefCell::new(vec![])),
            sign_options: RefCell::new(sign_options),
            error: RefCell::new(Ok(())),
        }
    }
}
