use std::collections::HashMap;

use actix_web::{get, post, web, HttpResponse, Responder};
use aes_gcm::aead::consts::True;
use jsonwebtoken::{encode, EncodingKey, Header};
use log::debug;
use rand::distributions::{Alphanumeric, DistString};
use serde::{Deserialize, Serialize};

use crate::{
    crypt::{self, EncryptionService},
    DBService, VaultEntry,
};

// AUTH

#[derive(Serialize, Deserialize)]
struct RegisterRequest {
    id: String,
    secret: String,
}
#[post("/register")]
async fn register(
    db: web::Data<DBService>,
    credentials: web::Json<RegisterRequest>,
) -> impl Responder {
    // TODO: pwd hashing
    debug!("Incoming register request.");
    let auth = db.auth.lock().unwrap();
    auth.load().unwrap();
    match auth.read(|users| users.contains_key(&credentials.id)) {
        Err(_) => HttpResponse::InternalServerError().body("DB error reading users!"),
        Ok(user_exists) => match user_exists {
            true => return HttpResponse::Unauthorized().body("User already exists!"),
            false => {
                debug!("Creating new user.");
                match auth
                    .write(|users| users.insert(credentials.id.clone(), credentials.secret.clone()))
                {
                    Ok(write_option) => match write_option {
                        Some(_) | None => {
                            auth.save().unwrap();
                            return HttpResponse::Ok().body("User created!");
                        }
                    },
                    Err(_) => {
                        return HttpResponse::InternalServerError()
                            .body("DB failed to create user!")
                    }
                }
            }
        },
    }
}

#[derive(Serialize, Deserialize)]
struct LoginRequest {
    id: String,
    secret: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    id: String,
}

#[derive(Serialize, Deserialize)]
struct LoginResponse {
    token: String,
}

#[post("/login")]
async fn login(
    db: web::Data<DBService>,
    credentials: web::Json<LoginRequest>,
    crypt: web::Data<EncryptionService>,
) -> impl Responder {
    let auth = db.auth.lock().unwrap();
    let data = auth.get_data(false).unwrap();
    match data.get(&credentials.id) {
        Some(secret) => match *secret == credentials.secret {
            true => {
                let claims = Claims {
                    id: credentials.id.clone(),
                };
                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(crypt.jwt_secret.as_bytes()),
                )
                .unwrap();
                return HttpResponse::Ok().json(LoginResponse { token });
            }
            false => return HttpResponse::Unauthorized().body("Wrong credentials!"),
        },
        None => return HttpResponse::Unauthorized().body("User not found!"),
    };
}

// TOKENIZE
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

//DETOKENIZE
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
