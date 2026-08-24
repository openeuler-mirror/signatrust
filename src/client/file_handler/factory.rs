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

use super::efi::EfiFileHandler;
use super::generic::GenericFileHandler;
use super::ima::ImaFileHandler;
use super::kernel_module::KernelModuleFileHandler;
use super::p7s::CmsFileHandler;
use super::rpm::RpmFileHandler;
use super::traits::FileHandler;
use crate::util::sign::FileType;

pub struct FileHandlerFactory {}

impl FileHandlerFactory {
    pub fn get_handler(file_type: &FileType) -> Box<dyn FileHandler> {
        match file_type {
            FileType::Rpm => Box::new(RpmFileHandler::new()),
            FileType::Generic => Box::new(GenericFileHandler::new()),
            FileType::KernelModule => Box::new(KernelModuleFileHandler::new()),
            FileType::EfiImage => Box::new(EfiFileHandler::new()),
            FileType::ImaEvm => Box::new(ImaFileHandler::new()),
            FileType::P7s => Box::new(CmsFileHandler::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_get_handler_rpm() {
        let handler = FileHandlerFactory::get_handler(&FileType::Rpm);
        // verify we get a handler (validate_options on RPM without options should succeed)
        assert!(handler.validate_options(&mut HashMap::new()).is_ok());
    }

    #[test]
    fn test_get_handler_generic() {
        let handler = FileHandlerFactory::get_handler(&FileType::Generic);
        assert!(handler.validate_options(&mut HashMap::new()).is_ok());
    }

    #[test]
    fn test_get_handler_kernel_module() {
        let handler = FileHandlerFactory::get_handler(&FileType::KernelModule);
        assert!(handler.validate_options(&mut HashMap::new()).is_ok());
    }

    #[test]
    fn test_get_handler_efi() {
        let handler = FileHandlerFactory::get_handler(&FileType::EfiImage);
        assert!(handler.validate_options(&mut HashMap::new()).is_ok());
    }

    #[test]
    fn test_get_handler_ima() {
        let handler = FileHandlerFactory::get_handler(&FileType::ImaEvm);
        assert!(handler.validate_options(&mut HashMap::new()).is_ok());
    }

    #[test]
    fn test_get_handler_p7s() {
        let handler = FileHandlerFactory::get_handler(&FileType::P7s);
        assert!(handler.validate_options(&mut HashMap::new()).is_ok());
    }
}
