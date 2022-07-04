use axum::{extract::Path, Extension, Json};

use blake2::{Blake2b, Blake2b512, Digest};

use hyper::StatusCode;
use jsonwebtoken::{encode, Header};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{query, PgPool};
use sqlx_core::transaction;

use crate::{
    db::{internal_error, DatabaseConnection},
    obj::{AuthBody, AuthError, Claims, UserAuth, UserSignUp, KEYS}, logic::{get_hash, generate_claim},
};

#[derive(Debug, sqlx::FromRow)]
struct UserDbAuth {
    uid: String,
    name: String
}

//==============================[protected for authorization]====================================
pub async fn protected(
    Json(payload): Json<UserAuth>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<AuthBody>, AuthError> {
    tracing::log::info!("payload: {:?}", payload);

    let hash  = get_hash(&payload.secret);

    //TODO try converting the seleciton of all the field to the count only for i32 type i.e. COUNT(*) instead of
    let resp = format!(
        "select public.jwt_user.uid, name from public.user_auth  
        inner join public.jwt_user 
        on jwt_user.uid = user_auth.uid  where user_auth.email = '{}' and user_auth.hash = '{}'  ",
        payload.userid,
        hash.to_string().as_str()
    );

    //TODO implement proper functoin for query checking the presense of user in database
    match sqlx_core::query_as::query_as::<sqlx_core::postgres::Postgres, UserDbAuth>(resp.as_str())
        .fetch_one(&pool)
        .await
    {
        Ok(r) => {
            tracing::log::info!("user : {:?}", r);
            
            let body = generate_claim(r.name, r.uid)
            .map_err(|e| return e)?;

            return Ok(Json(AuthBody::new(body)));
        }
        Err(_) => {
            tracing::log::error!("user not found in database");

            return Err(AuthError::WrongCredentials);
        }
    }
}

//==============================[db transaction]====================================
use std::error::Error;

async fn insert_user(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    name: &String,
    email: &String,
    pw: &str,
) -> Result<String, Box<dyn Error>> {
    let uid = uuid::Uuid::new_v4().to_string();
    tracing::log::info!("uid:  {}", uid);

    match sqlx::query::<sqlx::Postgres>(
        format!(
            " INSERT INTO public.jwt_user(uid, name, email) values ('{}', '{}', '{}') ",
            uid.clone(),
            name,
            email
        )
        .as_str(),
    )
    .execute(&mut *transaction)
    .await
    {
        Err(e) => {
            tracing::log::error!("user insertion failed: {}", e);
            return Err(Box::new(e));
        }
        _ => {
            tracing::log::info!("insertion is succesfull to jwt_user");
        }
    };

    match sqlx::query::<sqlx::Postgres>(
        format!(
            " INSERT INTO public.user_auth(uid, email, hash) values ('{}', '{}', '{}')",
            uid.clone(),
            email,
            pw
        )
        .as_str(),
    )
    .execute(&mut *transaction)
    .await
    {
        Err(e) => {
            tracing::log::error!(" auth insertion failed: {}", e);
            return Err(Box::new(e));
        }
        _ => {
            tracing::log::info!("insertion is succesfull to jwt_user");
        }
    };

    return Ok(uid);
}

async fn commit_to_db(
    pool: &sqlx::PgPool,
    payload: &UserSignUp,
    hash: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut transaction = pool.begin().await?;

    let uid = match insert_user(
        &mut transaction,
        &(payload.name),
        &(payload.client_id),
        hash,
    )
    .await
    {
        Ok(f) => f,
        Err(e) => {
            return Err(e);
        }
    };

    transaction.commit().await?;

    Ok(uid)
}

//==============================[authentication]====================================

pub async fn sign_up(
    Path(id): Path<String>,
    Json(payload): Json<UserSignUp>,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }

    tracing::log::info!("called sign up");
    //let mut transaction = pool.clone().begin().await.unwrap();

    tracing::log::info!("client secret: {:?}", payload.client_secret.as_bytes());

    //TODO insert improved hash function for this function to increase the compute speed

    let hash = get_hash(&payload.client_secret);

    tracing::log::info!(" hash: {:?}", hash);

    let db_res = commit_to_db(&pool, &payload, &hash).await;

    match db_res {
        //TODO add expirey time for claims from settings.toml
        //TODO  extract keys for jwt secret from the settings.toml instead of env:

        //TODO
        Ok(f) => {

            let token = generate_claim(payload.name, f)
            .map_err(|e| return e)?;
            // Send the authorized token
            return Ok(Json(AuthBody::new(token)));
        }
        Err(e) => {
            return Err(AuthError::WrongCredentials);
        }
    }
}

//==============================[connection pool extractor]====================================

#[derive(sqlx::FromRow, Serialize, Debug)]
pub struct jwt {
    pub uid: String,
    pub name: String,
    pub email: String,
}

// ambitious
// unfocused
// social skill ruined

pub async fn using_connection_pool_extractor(
    claim: Claims,
    Extension(pool): Extension<PgPool>,
) -> Result<Json<Vec<jwt>>, (StatusCode, String)> {
    let resp = format!(
        "select * from public.jwt_user  where uid = '{}'",
        claim.user_uid
    );

    //sqlx_core::postgres::Postgres;

    match sqlx_core::query_as::query_as::<sqlx_core::postgres::Postgres, jwt>(resp.as_str())
        .fetch_all(&pool)
        .await
    {
        Ok(v) => {
            //println!("v: {:?}", v);
            let mut u: String = " ".to_string();

            for i in v.iter() {
                let y = &serde_json::to_string(i).unwrap();
                u += format!("{:?} \n", y).as_str();
            }

            return Ok(Json(v));
        }
        Err(f) => {
            tracing::log::error!("");
            return Err((StatusCode::NOT_FOUND, "not found in auth".to_string()));
        }
    }
}
//==============================[connection pool extractor]====================================

use uuid::Uuid;

pub async fn using_connection_extractor(
    claim: Claims,
    DatabaseConnection(conn): DatabaseConnection,
) -> Result<String, (StatusCode, String)> {
    let mut conn = conn;

    let uid = Uuid::new_v4().as_hyphenated().to_string();
    //let name = Uuid::new_v4().as_hyphenated().to_string();

    let query = format!(
        "INSERT INTO jwt_user (uid, name, email) VALUES ('{}', '{}', '{}');",
        uid, "arun", "arun@something"
    );

    sqlx::query_scalar(query.as_str())
        .fetch_one(&mut conn)
        .await
        .map_err(internal_error)
}
