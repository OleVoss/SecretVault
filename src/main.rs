mod crypt;

use actix_web::{
    get, post,
    web::{self, Data},
    App, HttpResponse, HttpServer, Responder,
};
use crypt::EncryptionService;
use rand::{
    distributions::{Alphanumeric, DistString},
    RngCore,
};
use rustbreak::{deser::Ron, FileDatabase};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, Mutex},
};
#[derive(Serialize, Deserialize)]
pub struct TokenizeBody {
    pub id: String,
    pub data: HashMap<String, Option<String>>,
}

impl TokenizeBody {
    pub fn new(id: String) -> Self {
        Self {
            id,
            data: HashMap::default(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DetokenizeResponse {
    pub id: String,
    pub data: HashMap<String, Field>,
}

impl DetokenizeResponse {
    pub fn new(id: String) -> Self {
        Self {
            id,
            data: HashMap::default(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DetokenizeRequest {
    pub id: String,
    pub data: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct Field {
    pub found: bool,
    pub value: String,
}

#[post("/tokenize")]
async fn tokenize(
    request_body: web::Json<TokenizeBody>,
    crypt: web::Data<crypt::EncryptionService>,
    db: web::Data<DBService>,
) -> impl Responder {
    let mut response_body = TokenizeBody::new(request_body.id.clone());
    response_body.data = request_body
        .data
        .clone()
        .into_iter()
        .map(|field| {
            let token = Alphanumeric.sample_string(&mut rand::thread_rng(), 7);

            // encrypt fields
            match crypt.encrypt(&field.1.unwrap_or("".to_string())) {
                Ok((encrypted, nonce)) => {
                    // safe encrypted data
                    match db.vault.lock().unwrap().write(|vault| {
                        vault.insert(token.clone(), VaultEntry::from(encrypted, nonce))
                    }) {
                        Ok(_) => (),
                        Err(_) => return (field.0.to_owned(), None),
                    }

                    return (field.0.to_owned(), Some(token));
                }
                Err(_) => return (field.0.to_owned(), None),
            }
        })
        .collect();
    return HttpResponse::Ok().json(response_body);
}

#[get("/detokenize")]
async fn detokenize(
    request_body: web::Json<DetokenizeRequest>,
    db: web::Data<DBService>,
    crypt: web::Data<EncryptionService>,
) -> impl Responder {
    let mut response_body = DetokenizeResponse::new(request_body.id.clone());

    // TODO: Fix panic on unwrap
    response_body.data = request_body
        .data
        .clone()
        .into_iter()
        .map(|field| {
            match db
                .vault
                .lock()
                .unwrap()
                .borrow_data()
                .unwrap()
                .get(&field.1)
            {
                Some(vault_entry) => {
                    let decrypted = match crypt.decrypt(&vault_entry.data, &vault_entry.nonce) {
                        Ok(d) => d,
                        Err(_) => "Error: decryption failed".to_string(),
                    };

                    return (
                        field.0,
                        Field {
                            found: true,
                            value: decrypted,
                        },
                    );
                }
                None => (
                    field.0.clone(),
                    Field {
                        found: false,
                        value: "Error: Error reading from db".to_string(),
                    },
                ),
            }
        })
        .collect();
    HttpResponse::Ok().json(response_body)
}

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
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    let encryption_service = crypt::EncryptionService::new(&key);
    let db_service = DBService {
        vault: Arc::new(Mutex::new(
            FileDatabase::<HashMap<String, VaultEntry>, Ron>::load_from_path_or_default(
                "vault.ron",
            )
            .unwrap(),
        )),
    };

    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();
    HttpServer::new(move || {
        App::new()
            .service(tokenize)
            .service(detokenize)
            .app_data(Data::new(db_service.clone()))
            .app_data(Data::new(encryption_service.clone()))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
