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

use super::rpm::RpmFileHandler;
use super::efi::EfiFileHandler;
use super::checksum::CheckSumFileHandler;
use super::kernel_module::KernelModuleFileHandler;
use crate::client::sign_identity::FileType;
use super::traits::FileHandler;

pub struct FileHandlerFactory {
}

impl FileHandlerFactory {
    pub fn get_handler(file_type: &FileType) -> Box<dyn FileHandler> {
        match file_type {
            FileType::RPM => {
                Box::new(RpmFileHandler::new())
            },
            FileType::CheckSum => {
                Box::new(CheckSumFileHandler::new())
            },
            FileType::KernelModule => {
                Box::new(KernelModuleFileHandler::new())
            },
            FileType::EfiImage => {
                Box::new(EfiFileHandler::new())
            },
        }
    }
}