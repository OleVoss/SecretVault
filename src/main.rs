mod api;
mod crypt;
mod middleware;

use actix_web::{web::Data, App, HttpServer};
use rand::RngCore;
use rustbreak::{deser::Ron, FileDatabase};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default, Eq, PartialEq, Debug, Serialize, Deserialize, Clone)]
struct VaultEntry {
    data: String,
    nonce: String,
}

impl VaultEntry {
    pub fn from(data: String, nonce: String) -> Self {
        Self { data, nonce }
    }
}

#[derive(Clone)]
struct DBService {
    pub vault: Arc<Mutex<FileDatabase<HashMap<String, VaultEntry>, Ron>>>,
    pub auth: Arc<Mutex<FileDatabase<HashMap<String, String>, Ron>>>,
}

// TODO: Custom errors
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    let encryption_service = crypt::EncryptionService::new(&key);

    let db_service = DBService {
        vault: Arc::new(Mutex::new(
            FileDatabase::<HashMap<String, VaultEntry>, Ron>::load_from_path_or_default(
                "./vault.ron",
            )
            .unwrap(),
        )),
        auth: Arc::new(Mutex::new(
            FileDatabase::<HashMap<String, String>, Ron>::load_from_path_or_default("./auth.ron")
                .unwrap(),
        )),
    };

    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();
    HttpServer::new(move || {
        App::new()
            .service(api::register)
            .service(api::login)
            .service(api::tokenize)
            .service(api::detokenize)
            .app_data(Data::new(db_service.clone()))
            .app_data(Data::new(encryption_service.clone()))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
