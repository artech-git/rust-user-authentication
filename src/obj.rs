use std::collections::HashMap;
use std::fmt::Display;

use axum::BoxError;
use axum::body::HttpBody;
use axum::extract::TypedHeader;
use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    response::{IntoResponse, Response},
    Json,
};
use headers::{authorization::Bearer, Authorization};
use hyper::StatusCode;
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::logic::{check_email, check_password, check_name};
//=======================================================================================================

pub static KEYS: Lazy<Keys> = Lazy::new(|| {
    
    let secret = match KEY_MAP.get(&"secret".to_string() ){

        Some(value) => {
            value.to_owned()
        }
        None => {
            tracing::log::error!("please insert secret parameter in settings.toml");
            panic!();
        }
    };

    Keys::new(secret.as_bytes())
});

pub static KEY_MAP: Lazy<HashMap<String, String>> = Lazy::new( || {

    let settings = match config::Config::builder() 
        .add_source(config::File::with_name("./Settings.toml"))
        .add_source(config::Environment::with_prefix("APP"))
        .build()
        {
            Ok(file) => file ,
            Err(e) => {
                tracing::log::error!("settings.toml file not found: {}",  e);
                panic!();
            }
        };

    let value_map = match settings
        .try_deserialize::<std::collections::HashMap<String, String>>()
        {
            Ok(values) => values,
            Err(e) => {
                tracing::log::error!("deserialization error of config variable: {}", e);
                panic!();
            }
        };
    
    value_map        
});

//=======================================================================================================
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub user_uid: String,
    pub exp: usize,
}

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Email: {}\nCompany: {}", self.sub, self.user_uid)
    }
}

#[async_trait]
impl<B> FromRequest<B> for Claims
where
    B: Send,
{
    type Rejection = AuthError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req)
                .await
                .map_err(|_| AuthError::InvalidToken)?;

        // Decode the user data
        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}
//=======================================================================================================

#[derive(Debug, Serialize)]
pub struct AuthBody {
    access_token: String,
    token_type: String,
}

impl AuthBody {
    pub fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
        }
    }
}
//=======================================================================================================

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
    InternalError
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
            AuthError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "unkown error")
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}
//=======================================================================================================
pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}
//=======================================================================================================

#[derive(Debug, Deserialize)]
pub struct UserSignUp {
    pub client_id: String,
    pub client_secret: String,
    pub name: String,
}

#[async_trait]
impl<B> FromRequest<B> for UserSignUp
where
    B: Send + HttpBody,
    B::Data: Send,
    B::Error: Into<BoxError>, 
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let Json(payload) = req.extract::<Json<UserSignUp>>().await.unwrap();

        if !check_email(&payload.client_secret) {
            return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid email type"));
        }
        if !check_password(&payload.client_id) {
            return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid password format"));
        }
        if !check_name(&payload.name) {
            return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid name format"));
        }
        Ok(payload)
    }
}
//=======================================================================================================
#[derive(sqlx::FromRow, Serialize, Debug)]
pub struct JwtUser {
    uid: String,
    name: String,
    email: String,
}
//=======================================================================================================

#[derive(Debug, Deserialize)]
pub struct UserAuth {
    pub userid: String,
    pub secret: String,
}

impl UserAuth {
    pub(crate) fn is_empty(&self) -> bool {
        if self.secret.is_empty() || self.userid.is_empty() {
            return false;
        }

        return true;
    }
}
//=======================================================================================================
#[derive(Debug, sqlx::FromRow)]
pub struct UserDbAuth {
    pub uid: String,
    pub name: String
}
//=======================================================================================================
