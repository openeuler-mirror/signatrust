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

use actix_web::{
    HttpResponse, Responder, Result, web, Scope
};


use crate::presentation::handler::control::model::datakey::dto::{DataKeyDTO, ExportKey};
use crate::util::error::Error;
use validator::Validate;
use crate::application::datakey::KeyService;
use crate::domain::datakey::entity::DataKey;
use super::model::user::dto::UserIdentity;

/// Create new key
///
/// This will generate either a pgp private/public key pairs or a x509 private/public/cert keys.
/// ## Generate pgp key
/// To generate a pgp key the required parameters in `attributes` are:
/// 1. **digest_algorithm**: the digest algorithm used for pgp, for example: sha2_256
/// 2. **email**: email address used for identify the pgp key,
/// 3. **key_length**: the private key length, for example, 2048,
/// 4. **key_type**: the algorithm of private key, for example, rsa or dsa.
/// ### Request body example:
/// ```json
/// {
///   "name": "test-pgp",
///   "email": "tommylikehu@gmail.com",
///   "description": "hello world",
///   "key_type": "pgp",
///   "user": "tommylike",
///   "attributes": {
///     "digest_algorithm": "sha2_256",
///     "key_type": "rsa",
///     "key_length": "2048",
///     "email": "test@openeuler.org",
///   },
///   "create_at": "2023-04-12 22:10:57+08:00",
///   "expire_at": "2024-05-12 22:10:57+08:00"
/// }
/// ```
///
/// ## Generate x509 key
/// To generate a x509 key the required parameters in `attributes` are:
/// 1. **digest_algorithm**: the digest algorithm used for x509 key, for example: sha2_256
/// 2. **key_length**: the private key length, for example, 2048,
/// 3. **key_type**: the algorithm of private key, for example, rsa or dsa.
/// 4. **common_name**: common name (commonName, CN), used for certificate.
/// 5. **country_name**: country (countryName, C), used for certificate.
/// 6. **locality**: locality (locality, L), used for certificate.
/// 7. **organization**: organization (organizationName, O), used for certificate.
/// 8. **organizational_unit**: organizational unit (organizationalUnitName, OU), used for certificate.
/// 9. **province_name**: state or province name (stateOrProvinceName, ST), used for certificate.
/// ### Request body example:
/// ```json
/// {
///   "name": "test-x509",
///   "email": "tommylikehu@gmail.com",
///   "description": "hello world",
///   "key_type": "x509",
///   "user": "tommylike",
///   "attributes": {
///     "digest_algorithm": "sha2_256",
///     "key_type": "rsa",
///     "key_length": "2048",
///     "common_name": "common name",
///     "organizational_unit": "organizational_unit",
///     "organization": "organization",
///     "locality": "locality",
///     "province_name": "province_name",
///     "country_name": "country_name"
///   },
///   "create_at": "2023-04-12 22:10:57+08:00",
///   "expire_at": "2024-05-12 22:10:57+08:00"
/// }
/// ```
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys -d '{}'
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys",
    request_body = DataKeyDTO,
    security(
    ("Authorization" = [])
    ),
    responses(
    (status = 201, description = "Key successfully imported", body = DataKeyDTO),
    (status = 400, description = "Bad request", body = ErrorMessage),
    (status = 401, description = "Unauthorized", body = ErrorMessage),
    (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn create_data_key(user: UserIdentity, key_service: web::Data<dyn KeyService>, datakey: web::Json<DataKeyDTO>,) -> Result<impl Responder, Error> {
    datakey.validate()?;
    let mut key = DataKey::convert_from(datakey.0, user)?;
    Ok(HttpResponse::Created().json(DataKeyDTO::try_from(key_service.into_inner().create(&mut key).await?)?))
}

/// Get all available keys from database.
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl https://domain:port/api/v1/keys/
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/keys/",
    security(
    ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "List available keys", body = [DataKeyDTO]),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn list_data_key(_user: UserIdentity, key_service: web::Data<dyn KeyService>) -> Result<impl Responder, Error> {
    let keys = key_service.into_inner().get_all().await?;
    let mut results = vec![];
    for k in keys {
        results.push(DataKeyDTO::try_from(k)?)
    }
    Ok(HttpResponse::Ok().json(results))
}

/// Get detail of specific key by id from database
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl https://domain:port/api/v1/keys/{id}
/// ```
#[utoipa::path(
    get,
    path = "/api/v1/keys/{id}",
    params(
        ("id" = i32, Path, description = "Key id"),
    ),
    security(
    ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "List available keys", body = DataKeyDTO),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn show_data_key(_user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    let key = key_service.into_inner().get_one(id.parse::<i32>()?).await?;
    Ok(HttpResponse::Ok().json(DataKeyDTO::try_from(key)?))
}

/// Delete specific key by id from database
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X DELETE https://domain:port/api/v1/keys/{id}
/// ```
#[utoipa::path(
    delete,
    path = "/api/v1/keys/{id}",
    params(
        ("id" = i32, Path, description = "Key id"),
    ),
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Key successfully deleted"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn delete_data_key(_user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    key_service.into_inner().delete_one(id.parse::<i32>()?).await?;
    Ok(HttpResponse::Ok())
}

/// Export content of specific key
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id}/export
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/{id}/export",
    params(
        ("id" = i32, Path, description = "Key id"),
    ),
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Key successfully exported", body = ExportKey),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn export_data_key(_user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    Ok(HttpResponse::Ok().json(ExportKey::try_from(key_service.export_one(id.parse::<i32>()?).await?)?))
}

/// Enable specific key
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id}/enable
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/{id}/enable",
    params(
        ("id" = i32, Path, description = "Key id"),
    ),
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Key successfully enabled"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn enable_data_key(_user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    key_service.enable(id.parse::<i32>()?).await?;
    Ok(HttpResponse::Ok())
}

/// Disable specific key
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id}/disable
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/{id}/disable",
    params(
        ("id" = i32, Path, description = "Key id"),
    ),
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Key successfully disabled"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn disable_data_key(_user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    key_service.disable(id.parse::<i32>()?).await?;
    Ok(HttpResponse::Ok())
}

/// Import key
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/import
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/import",
    request_body = DataKeyDTO,
    security(
    ("Authorization" = [])
    ),
    responses(
        (status = 201, description = "Key successfully imported", body = DataKeyDTO),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn import_data_key(_user: UserIdentity) -> Result<impl Responder, Error> {
    Ok(HttpResponse::Created())
}


pub fn get_scope() -> Scope {
    web::scope("/keys")
        .service(
            web::resource("/")
                .route(web::get().to(list_data_key))
                .route(web::post().to(create_data_key)))
        .service( web::resource("/{id}")
            .route(web::get().to(show_data_key))
            .route(web::delete().to(delete_data_key)))
        .service( web::resource("/import").route(web::post().to(import_data_key)))
        .service( web::resource("/{id}/export").route(web::post().to(export_data_key)))
        .service( web::resource("/{id}/enable").route(web::post().to(enable_data_key)))
        .service( web::resource("/{id}/disable").route(web::post().to(disable_data_key)))
}
