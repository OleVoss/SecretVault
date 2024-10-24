use actix_web::{
    get, post,
    web::{self, Data},
    App, HttpResponse, HttpServer, Responder,
};
use log::debug;
use rand::distributions::{Alphanumeric, DistString};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Mutex};
#[derive(Serialize, Deserialize)]
pub struct TokenizeBody {
    pub id: String,
    pub data: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct DetokenizeResponse {
    pub id: String,
    pub data: HashMap<String, Field>,
}
#[derive(Serialize, Deserialize)]
pub struct Field {
    pub found: bool,
    pub value: String,
}

#[post("/tokenize")]
async fn tokenize(mut body: web::Json<TokenizeBody>, vault: web::Data<AppState>) -> impl Responder {
    body.data.iter_mut().for_each(|field| {
        let token = Alphanumeric.sample_string(&mut rand::thread_rng(), 7);
        vault
            .secret_data
            .lock()
            .unwrap()
            .insert(token.clone(), field.1.clone());
        *field.1 = token;
    });
    debug!("{:?}", vault.secret_data);
    HttpResponse::Ok().json(body)
}
#[get("/detokenize")]
async fn detokenize(body: web::Json<TokenizeBody>, vault: web::Data<AppState>) -> impl Responder {
    let mut data: HashMap<String, Field> = HashMap::default();
    body.data.iter().for_each(
        |field| match vault.secret_data.lock().unwrap().get(field.1) {
            Some(v) => {
                data.insert(
                    field.0.clone(),
                    Field {
                        found: true,
                        value: v.clone(),
                    },
                );
            }
            None => {
                data.insert(
                    field.0.clone(),
                    Field {
                        found: false,
                        value: "not found".to_string(),
                    },
                );
            }
        },
    );
    HttpResponse::Ok().json(DetokenizeResponse {
        id: body.id.clone(),
        data: data,
    })
}

#[derive(Default)]
struct AppState {
    pub secret_data: Mutex<HashMap<String, String>>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();
    HttpServer::new(|| {
        App::new()
            .service(tokenize)
            .service(detokenize)
            .app_data(Data::new(AppState::default()))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
