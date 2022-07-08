//! Example JWT authorization/authentication.
//!
//! Run with
//!
//! ```not_rust
//! JWT_SECRET=secret cargo run -p example-jwt
//! ```

use axum::{
    routing::{get, post},
    Extension, Router,
};

#[macro_use]
extern crate lazy_static;

//todo insert debug feature of tracing library where you can view the event of each transaction in terminal/file easily

use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;

mod db;
mod handler;
mod logic;
mod obj;

use crate::{
    handler::{protected, sign_up, using_connection_extractor, using_connection_pool_extractor},
    obj::KEY_MAP,
};

#[tokio::main]
async fn main() {
    // tracing_subscriber::registry()
    //     .with(tracing_subscriber::EnvFilter::new(
    //         std::env::var("RUST_LOG").unwrap_or_else(|_| "example_jwt=debug".into()),
    //     ))
    //     .with()
    //     .init();
    tracing_subscriber::fmt::init();
    tracing::log::info!("started main");

    let db_url = KEY_MAP.get(&"db_url".to_string()).unwrap();

    let pool = match PgPoolOptions::new()
        .max_connections(5)
        //.connect_timeout(Duration::from_secs(3))
        .connect(&db_url)
        .await
    {
        Ok(p) => {
            tracing::log::info!("connection succeed to database");
            p
        }
        Err(e) => {
            tracing::log::error!("connection to database failed:  {}", e);
            panic!();
        }
    };

    let app = Router::new()
        .route("/check", get(|| async{ "up".to_string() }))
        .route("/signup/:id", post(sign_up))
        .route("/auth/user/", get(protected))
        .route(
            "/auth/",
            get(using_connection_pool_extractor).post(using_connection_extractor),
        )
        .layer(Extension(pool));

    let port = KEY_MAP
        .get(&"port".to_string())
        .unwrap_or(&"3000".to_string())
        .parse::<u16>()
        .unwrap();

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
