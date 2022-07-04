use std::{collections::hash_map::DefaultHasher, hash::{Hash, Hasher}};

use axum::Json;
use jsonwebtoken::{Header, encode};

use crate::obj::{Claims, KEYS, AuthError, AuthBody};


pub fn get_hash(client_secret: &String) -> String {

    let mut hasher = DefaultHasher::new();

    client_secret.hash(&mut hasher);

    let hash = hasher.finish();
    
    hash.to_string()

}

pub fn generate_claim(sub: String, uid: String ) -> Result<String, AuthError> {

    let claims = Claims {
        sub: sub,
        user_uid: uid,
        // Mandatory expiry time as UTC timestamp
        exp: 3000000, 
    };

    // Create the authorization token
    let token = match encode(&Header::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation) {
            Ok(tok) => { tok }
            Err(e) => { return Err(e); }
        };

    // Send the authorized token
    return Ok(token);
}