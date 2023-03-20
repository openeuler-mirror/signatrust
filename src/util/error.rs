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

use config::ConfigError;
use pgp::composed::key::SecretKeyParamsBuilderError;
use pgp::errors::Error as PGPError;
use reqwest::header::{InvalidHeaderValue, ToStrError as StrError};
use reqwest::Error as RequestError;
use serde_json::Error as SerdeError;
use sqlx::Error as SqlxError;
use std::io::Error as IOError;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
use std::sync::PoisonError;
use rpm::RPMError;
use thiserror::Error as ThisError;
use tonic::transport::Error as TonicError;
use bincode::error::EncodeError;
use chrono::{OutOfRangeError, ParseError};
use actix_web::{ResponseError, HttpResponse};
use validator::ValidationErrors;
use serde::{Deserialize, Serialize};
use openssl::error::ErrorStack;
use actix_web::cookie::KeyError;
use openidconnect::url::ParseError as OIDCParseError;
use openidconnect::ConfigurationError;
use openidconnect::UserInfoError;

pub type Result<T> = std::result::Result<T, Error>;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, ThisError, Clone)]
pub enum Error {
    #[error("An error occurred in database operation. {0}")]
    DatabaseError(String),
    #[error("An error occurred when loading configure file. {0}")]
    ConfigError(String),
    #[error("An error occurred when perform IO requests. {0}")]
    IOError(String),
    #[error("unsupported type configured. {0}")]
    UnsupportedTypeError(String),
    #[error("kms invoke error. {0}")]
    KMSInvokeError(String),
    #[error("failed to serialize/deserialize. {0}")]
    SerializeError(String),
    #[error("failed to perform http request. {0}")]
    HttpRequest(String),
    #[error("failed to convert. {0}")]
    ConvertError(String),
    #[error("failed to encode/decode. {0}")]
    EncodeError(String),
    #[error("failed to get cluster key. {0}")]
    ClusterError(String),
    #[error("failed to serialize/deserialize key. {0}")]
    KeyParseError(String),
    #[error("failed to sign with key {0}. {1}")]
    SignError(String, String),
    #[error("failed to perform pgp {0}")]
    PGPInvokeError(String),
    #[error("failed to perform openssl {0}")]
    X509InvokeError(String),
    #[error("invalid parameter error {0}")]
    ParameterError(String),
    #[error("record not found error")]
    NotFoundError,
    #[error("invalid user")]
    UnauthorizedError,
    #[error("invalid cookie key found")]
    InvalidCookieKeyError,
    #[error("failed to perform auth operation: {0}")]
    AuthError(String),

    //client error
    #[error("file type not supported {0}")]
    FileNotSupportError(String),
    #[error("not any valid file found")]
    NoFileCandidateError,
    #[error("failed to split file: {0}")]
    SplitFileError(String),
    #[error("failed to remote sign file: {0}")]
    RemoteSignError(String),
    #[error("failed to assemble file: {0}")]
    AssembleFileError(String),
    #[error("failed to walk through directory: {0}")]
    WalkDirectoryError(String),
    #[error("failed to parse rpm file: {0}")]
    RpmParseError(String),
    #[error("invalid argument: {0}")]
    InvalidArgumentError(String),
    #[error("failed to encode in bincode: {0}")]
    BincodeError(String),
    #[error("failed to sign some of the files")]
    PartialSuccessError,
    #[error("kernel module file signed already")]
    KOAlreadySignedError,
}

#[derive(Deserialize, Serialize)]
pub struct ErrorMessage {
    detail: String
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        match self {
            Error::ParameterError(_) | Error::UnsupportedTypeError(_) => {
                warn!("parameter error: {}", self.to_string());
                HttpResponse::BadRequest().json(ErrorMessage{
                    detail: self.to_string()
                })
            }
            Error::NotFoundError => {
                warn!("record not found error: {}", self.to_string());
                HttpResponse::NotFound().json(ErrorMessage{
                    detail: self.to_string()
                })
            }
            Error::UnauthorizedError => {
                warn!("authorized: {}", self.to_string());
                HttpResponse::Unauthorized().json(ErrorMessage{
                    detail: self.to_string()
                })
            }
            _ => {
                warn!("internal error: {}", self.to_string());
                HttpResponse::InternalServerError().json(ErrorMessage{
                    detail: self.to_string(),
                })
            }
        }
    }
}

impl From<SqlxError> for Error {
    fn from(sqlx_error: SqlxError) -> Self {
        match sqlx_error.as_database_error() {
            Some(db_error) => Error::DatabaseError(db_error.to_string()),
            None => {
                match sqlx_error {
                    sqlx::Error::RowNotFound => {
                        Error::NotFoundError
                    },
                    _ => {
                        error!("{:?}", sqlx_error);
                        Error::DatabaseError(format!("Unrecognized database error! {:?}", sqlx_error))
                    }
                }

            }
        }
    }
}

impl From<ParseIntError> for Error {
    fn from(error: ParseIntError) -> Self {
        Error::ConfigError(error.to_string())
    }
}

impl From<IOError> for Error {
    fn from(error: IOError) -> Self {
        Error::IOError(error.to_string())
    }
}


impl<T> From<PoisonError<T>> for Error {
    fn from(error: PoisonError<T>) -> Self {
        Error::ConfigError(error.to_string())
    }
}

impl From<ConfigError> for Error {
    fn from(error: ConfigError) -> Self {
        Error::ConfigError(error.to_string())
    }
}

impl From<SerdeError> for Error {
    fn from(error: SerdeError) -> Self {
        Error::SerializeError(error.to_string())
    }
}

impl From<StrError> for Error {
    fn from(error: StrError) -> Self {
        Error::ConvertError(error.to_string())
    }
}

impl From<InvalidHeaderValue> for Error {
    fn from(error: InvalidHeaderValue) -> Self {
        Error::HttpRequest(error.to_string())
    }
}

impl From<RequestError> for Error {
    fn from(error: RequestError) -> Self {
        Error::HttpRequest(error.to_string())
    }
}

impl From<AddrParseError> for Error {
    fn from(error: AddrParseError) -> Self {
        Error::ConfigError(error.to_string())
    }
}

impl From<TonicError> for Error {
    fn from(error: TonicError) -> Self {
        Error::ConfigError(error.to_string())
    }
}

impl From<FromUtf8Error> for Error {
    fn from(error: FromUtf8Error) -> Self {
        Error::ConvertError(error.to_string())
    }
}

impl From<PGPError> for Error {
    fn from(error: PGPError) -> Self {
        Error::PGPInvokeError(error.to_string())
    }
}

impl From<SecretKeyParamsBuilderError> for Error {
    fn from(error: SecretKeyParamsBuilderError) -> Self {
        Error::PGPInvokeError(error.to_string())
    }
}

impl From<walkdir::Error> for Error {
    fn from(err: walkdir::Error) -> Self {
        Error::WalkDirectoryError(err.to_string())
    }
}

impl From<RPMError> for Error {
    fn from(err: RPMError) -> Self {
        Error::RpmParseError(err.to_string())
    }
}

impl From<EncodeError> for Error {
    fn from(err: EncodeError) -> Self {
        Error::BincodeError(err.to_string())
    }
}

impl From<OutOfRangeError> for Error {
    fn from(err: OutOfRangeError) -> Self {
        Error::ConvertError(err.to_string())
    }
}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Self {
        Error::ConvertError(err.to_string())
    }
}

impl From<ValidationErrors> for Error {
    fn from(err: ValidationErrors) -> Self {
        Error::ParameterError(format!("{:?}", err.errors()))
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Error::X509InvokeError(format!("{:?}", err.errors()))
    }
}

impl From<KeyError> for Error {
    fn from(_: KeyError) -> Self {
        Error::InvalidCookieKeyError
    }
}

impl From<OIDCParseError> for Error {
    fn from(err: OIDCParseError) -> Self {
        Error::ConfigError(err.to_string())
    }
}

impl From<ConfigurationError> for Error {
    fn from(err: ConfigurationError) -> Self {
        Error::AuthError(err.to_string())
    }
}

impl From<UserInfoError<openidconnect::reqwest::Error<reqwest::Error>>> for Error {
    fn from(err: UserInfoError<openidconnect::reqwest::Error<reqwest::Error>>) -> Self {
    Error::AuthError(err.to_string())
}
}



