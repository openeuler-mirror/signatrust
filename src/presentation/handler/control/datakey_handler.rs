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

use std::str::FromStr;
use actix_web::{
    HttpResponse, Responder, Result, web, Scope
};


use crate::presentation::handler::control::model::datakey::dto::{CreateDataKeyDTO, DataKeyDTO, ExportKey, ImportDataKeyDTO, KeyQuery, NameIdenticalQuery};
use crate::util::error::Error;
use validator::Validate;
use crate::application::datakey::KeyService;
use crate::domain::datakey::entity::{DataKey, Visibility};
use super::model::user::dto::UserIdentity;

/// Create new key
///
/// This will generate either a pgp private/public key pairs or a x509 private/public/cert keys.
/// ## Naming convention
/// The name of the key should be unique, and if you want to create a private key, the name will be prefixed with your email address automatically,
/// for example you will get `youremail@address.com:some-private-key-name` when you specify the private key named `some-private-key-name`.
/// ## Generate pgp key
/// To generate a pgp key the required parameters in `attributes` are:
/// 1. **digest_algorithm**: the digest algorithm used for pgp, for example: sha2_256
/// 2. **email**: email address used for identify the pgp key,
/// 3. **key_length**: the private key length, for example, 2048,
/// 4. **key_type**: the algorithm of private key, for example, rsa or dsa.
/// 5. **passphrase**: (optional) password of the key
/// ### Request body example:
/// ```json
/// {
///   "name": "test-pgp",
///   "description": "hello world",
///   "key_type": "pgp",
///   "visibility": "public",
///   "attributes": {
///     "digest_algorithm": "sha2_256",
///     "key_type": "rsa",
///     "key_length": "2048",
///     "email": "test@openeuler.org",
///     "passphrase": "password"
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
///   "description": "hello world",
///   "key_type": "x509",
///   "visibility": "public",
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
    path = "/api/v1/keys/",
    request_body = CreateDataKeyDTO,
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
async fn create_data_key(user: UserIdentity, key_service: web::Data<dyn KeyService>, datakey: web::Json<CreateDataKeyDTO>,) -> Result<impl Responder, Error> {
    datakey.validate()?;
    let mut key = DataKey::create_from(datakey.0, user)?;
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
    params(
        KeyQuery
    ),
    security(
    ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "List available keys", body = [DataKeyDTO]),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn list_data_key(user: UserIdentity, key_service: web::Data<dyn KeyService>, key_query: web::Query<KeyQuery>) -> Result<impl Responder, Error> {
    let key_visibility = Visibility::from_str(key_query.visibility.as_str())?;
    let keys = key_service.into_inner().get_all(Some(user), key_visibility).await?;
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
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn show_data_key(user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    let key = key_service.into_inner().get_one(Some(user), id.parse::<i32>()?).await?;
    Ok(HttpResponse::Ok().json(DataKeyDTO::try_from(key)?))
}

/// Delete specific key by id from database, only **disabled** key can be deleted.
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id}/request_delete
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/{id}/request_delete",
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
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn delete_data_key(user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    key_service.into_inner().request_delete(user, id.parse::<i32>()?).await?;
    Ok(HttpResponse::Ok())
}

/// Cancel deletion of specific key by id from database, it only works for **public key**.
///
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/{id}/cancel_delete
/// ```
#[utoipa::path(
post,
path = "/api/v1/keys/{id}/cancel_delete",
    params(
        ("id" = i32, Path, description = "Key id"),
        ),
    security(
        ("Authorization" = [])
        ),
    responses(
        (status = 200, description = "Key deletion canceled successfully"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 401, description = "Unauthorized", body = ErrorMessage),
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
)
)]
async fn cancel_delete_data_key(user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    key_service.into_inner().cancel_delete(user, id.parse::<i32>()?).await?;
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
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn export_data_key(user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    Ok(HttpResponse::Ok().json(ExportKey::try_from(key_service.export_one(Some(user), id.parse::<i32>()?).await?)?))
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
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn enable_data_key(user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    key_service.enable(Some(user), id.parse::<i32>()?).await?;
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
        (status = 403, description = "Forbidden", body = ErrorMessage),
        (status = 404, description = "Key not found", body = ErrorMessage),
        (status = 500, description = "Server internal error", body = ErrorMessage)
    )
)]
async fn disable_data_key(user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    key_service.disable(Some(user), id.parse::<i32>()?).await?;
    Ok(HttpResponse::Ok())
}

/// Check whether a key name already exists
///
/// Use this API to check whether the key name exists in database.
/// `name` and `visibility` are required
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/name_identical?name=xxx&visibility=xxx
/// ```
#[utoipa::path(
    head,
    path = "/api/v1/keys/name_identical",
    params(
        NameIdenticalQuery
    ),
    security(
        ("Authorization" = [])
    ),
    responses(
        (status = 200, description = "Name does not exist"),
        (status = 400, description = "Bad request", body = ErrorMessage),
        (status = 409, description = "Conflict in name")
    )
)]
async fn key_name_identical(user: UserIdentity, key_service: web::Data<dyn KeyService>, name_exist: web::Query<NameIdenticalQuery>,) -> Result<impl Responder, Error> {
    name_exist.validate()?;
    match key_service.into_inner().key_name_exists(&name_exist.get_key_name(&user)).await? {
        true => Ok(HttpResponse::Conflict()),
        false => Ok(HttpResponse::Ok()),
    }
}

/// Import key
///
/// Use this API to import openpgp or x509 keys
/// ## Import openPGP keys
/// `private_key` and `public_key` are required, and the content are represented in armored text format, for example:
/// ```text
///  -----BEGIN PGP PUBLIC KEY BLOCK-----
///  xsFNBGRDujMBEADwXafQySUIUvuO0e7vTzgW8KkgzAFDmR7CO8tVplcQS03oZmrm
///  ZhhjV+MnfsONMVzrAvusDIF4YnKSXGJI8Y4A21hsK6CV+1PxqCpcGqDQ88H1Gtd5
///  ........skipped content.......
///  vTw1M8qqdjRpJhdF8kNXZITlaMkLOwZuL3QvDvEORw41o8zgSN1ryQuN/HtSLOJr
///  IcJ//T9nn8hCPxkMZE2T7JBEZBQwbzGjI5nUZV6nS6caINfXtkoRbta1SXcoRBSe
///  L0fZUKYcKURCAbLmz0bcrOsDBqnK
///  =c1i2
/// -----END PGP PUBLIC KEY BLOCK-----
/// ```
/// you need to specify the `digest_algorithm`, `key_type`, `expire` and `key_length` in the `attributes` as well,
/// passphrase **MUST** be specified for accessing the imported keys which specified passphrase when generating.
/// ```json
/// "attributes": {
///     "digest_algorithm": "sha2_256"
///     "passphrase": "husheng@1234"
///     "key_type": "rsa",
///     "key_length": "2048",
///     "expire_at": "2024-07-12 22:10:57+08:00"
/// }
/// ```
/// ## Import openSSL x509 keys
/// `certificate` and `private` are required, and the content are represented in PEM format, for example:
/// ```text
/// -----BEGIN PRIVATE KEY-----
/// MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDrd/0ui/bc5PJS
/// Yo5eS9hD2M91NrJZPiF+vEdq/vOSypac9XukLjkhj1zADU2h35b1nMQoi0bG7SNr
/// ........skipped content.......
/// XTYUPye7CKt33tFhHYKj7EHvZmHkbmskpXdCiHpTZd4u84lwvH/acHfJ0Fqh0pV3
/// IHehlWfHhjCxtw5Kzl3ncrHA
/// -----END PRIVATE KEY-----
/// ```
/// you need to specify the `digest_algorithm`, `key_type`, `expire` and `key_length` in the `attributes` as well,
/// ```json
/// "attributes": {
///     "digest_algorithm": "sha2_256"
///     "key_type": "rsa",
///     "key_length": "2048",
///     "expire_at": "2024-07-12 22:10:57+08:00"
/// }
/// ## Example
/// Call the api endpoint with following curl.
/// ```text
/// curl -X POST https://domain:port/api/v1/keys/import
/// ```
#[utoipa::path(
    post,
    path = "/api/v1/keys/import",
    request_body = ImportDataKeyDTO,
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
async fn import_data_key(user: UserIdentity, key_service: web::Data<dyn KeyService>, datakey: web::Json<ImportDataKeyDTO>,) -> Result<impl Responder, Error> {
    datakey.validate()?;
    let mut key = DataKey::import_from(datakey.0, user)?;
    Ok(HttpResponse::Created().json(DataKeyDTO::try_from(key_service.into_inner().import(&mut key).await?)?))
}


pub fn get_scope() -> Scope {
    web::scope("/keys")
        .service(
            web::resource("/")
                .route(web::get().to(list_data_key))
                .route(web::post().to(create_data_key)))
        .service( web::resource("/import").route(web::post().to(import_data_key)))
        .service( web::resource("/name_identical").route(web::head().to(key_name_identical)))
        .service( web::resource("/{id}").route(web::get().to(show_data_key)))
        .service( web::resource("/{id}/export").route(web::post().to(export_data_key)))
        .service( web::resource("/{id}/enable").route(web::post().to(enable_data_key)))
        .service( web::resource("/{id}/disable").route(web::post().to(disable_data_key)))
        .service( web::resource("/{id}/request_delete").route(web::post().to(delete_data_key)))
        .service( web::resource("/{id}/cancel_delete").route(web::post().to(cancel_delete_data_key)))
}
