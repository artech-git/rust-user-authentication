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

use config::Config;

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod db;
mod handler;
mod obj;
mod logic;

// Quick instructions
//
// - get an authorization token:
//
// curl -s \
//     -w '\n' \
//     -H 'Content-Type: application/json' \
//     -d '{"client_id":"foo","client_secret":"bar"}' \
//     http://localhost:3000/authorize
//
// - visit the protected area using the authorized token
//
// curl -s \
//     -w '\n' \
//     -H 'Content-Type: application/json' \
//     -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjEwMDAwMDAwMDAwfQ.M3LAZmrzUkXDC1q5mSzFAs_kJrwuKz3jOoDmjJ0G4gM' \
//     http://localhost:3000/protected
//
// - try to visit the protected area using an invalid token
//
// curl -s \
//     -w '\n' \
//     -H 'Content-Type: application/json' \
//     -H 'Authorization: Bearer blahblahblah' \
//     http://localhost:3000/protected

use crate::{
    handler::{protected, sign_up, using_connection_extractor, using_connection_pool_extractor},
    obj::Claims,
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

    let settings = Config::builder() //TODO insert error handling for settings toml file
        // Add in `./Settings.toml`
        .add_source(config::File::with_name("./Settings.toml"))
        // Add in settings from the environment (with a prefix of APP)
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .add_source(config::Environment::with_prefix("APP"))
        .build()
        .unwrap();

    let value_map = settings
        .try_deserialize::<std::collections::HashMap<String, String>>()
        .unwrap();

    let db_url = value_map.get(&"db_url".to_string()).unwrap();

    let pool = PgPoolOptions::new()
        .max_connections(5)
        //.connect_timeout(Duration::from_secs(3))
        .connect(&db_url)
        .await
        .expect("postgresql connection failed");

    println!("values : {:?}", value_map);

    tracing::log::info!("{:?}", value_map);

    let app = Router::new()
        .route("/signup/:id", post(sign_up))
        .route("/auth/user/", get(protected))
        .route(
            "/auth/",
            get(using_connection_pool_extractor).post(using_connection_extractor),
        )
        .layer(Extension(pool));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
