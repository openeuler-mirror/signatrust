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


async fn create_data_key(user: UserIdentity, key_service: web::Data<dyn KeyService>, datakey: web::Json<DataKeyDTO>,) -> Result<impl Responder, Error> {
    datakey.validate()?;
    let mut key = DataKey::convert_from(datakey.0, user)?;
    Ok(HttpResponse::Created().json(DataKeyDTO::try_from(key_service.into_inner().create(&mut key).await?)?))
}

async fn list_data_key(_user: UserIdentity, key_service: web::Data<dyn KeyService>) -> Result<impl Responder, Error> {
    let keys = key_service.into_inner().get_all().await?;
    let mut results = vec![];
    for k in keys {
        results.push(DataKeyDTO::try_from(k)?)
    }
    Ok(HttpResponse::Ok().json(results))
}

async fn show_data_key(_user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    let key = key_service.into_inner().get_one(id.parse::<i32>()?).await?;
    Ok(HttpResponse::Ok().json(DataKeyDTO::try_from(key)?))
}

async fn delete_data_key(_user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    key_service.into_inner().delete_one(id.parse::<i32>()?).await?;
    Ok(HttpResponse::Ok())
}

async fn export_data_key(_user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    Ok(HttpResponse::Ok().json(ExportKey::try_from(key_service.export_one(id.parse::<i32>()?).await?)?))
}

async fn enable_data_key(_user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    key_service.enable(id.parse::<i32>()?).await?;
    Ok(HttpResponse::Ok())
}

async fn disable_data_key(_user: UserIdentity, key_service: web::Data<dyn KeyService>, id: web::Path<String>) -> Result<impl Responder, Error> {
    key_service.disable(id.parse::<i32>()?).await?;
    Ok(HttpResponse::Ok())
}

async fn import_data_key(_user: UserIdentity) -> Result<impl Responder, Error> {
    Ok(HttpResponse::Ok())
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
