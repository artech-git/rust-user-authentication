use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Header};
use regex::Regex;

use crate::obj::{AuthError, Claims, KEYS, KEY_MAP};

pub fn get_hash(client_secret: &String) -> String {

    let hash = match bcrypt::hash(client_secret.as_ref() as &str,  5) {
        Ok(f) => {
            f
        }
        Err(e) => {
            tracing::log::error!("error in creating a hash of client secret: {}", e);
            panic!();
        }
    };

    hash
}

fn get_exp_time_duration() -> i64 {
    match KEY_MAP.get(&"token_validity".to_string()) {
        Some(token) => match token.to_owned().parse::<i64>() {
            Ok(v) => return v,
            Err(v) => {
                tracing::log::error!("value must contain only numbers: {}", v);
                return 60 * 60;
            }
        },
        None => {
            tracing::log::error!("please insert token_validity parameter");
            return 60 * 60;
        }
    }
}

//todo set token validation IAT & EXP  in claims using chrono lib.
pub fn generate_claim(sub: String, uid: String) -> Result<String, AuthError> {
    let my_iat = Utc::now().timestamp();
    //let mut EXP = 0;
    lazy_static! {
        pub static ref EXPIRE: i64 = get_exp_time_duration();
    };

    let my_exp = Utc::now()
        .checked_add_signed(Duration::seconds(*EXPIRE))
        .expect("invalid timestamp")
        .timestamp();

    let claims = Claims {
        sub: sub,
        user_uid: uid,
        // Mandatory expiry time as UTC timestamp
        iat: my_iat as usize,
        exp: my_exp as usize,
    };

    // Create the authorization token
    let token = match encode(&Header::default(), &claims, &KEYS.encoding)
        .map_err(|_| AuthError::TokenCreation)
    {
        Ok(tok) => tok,
        Err(e) => {
            return Err(e);
        }
    };

    // Send the authorized token
    return Ok(token);
}

//todo validation is failing .. diagnose the issue for signup route
//==================================[credential validation functions]======================================
pub fn check_email(email: &String) -> bool {
    lazy_static! {//todo evaluate the email constrain too
        static ref RE: Regex = Regex::new(r"/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/").unwrap();
    }
    RE.is_match(email)
}

pub fn check_password(pw: &String) -> bool {
    lazy_static! {//todo evaluate the regex matching more carefullyt for certain constrains
        static ref RE: Regex = Regex::new(r"((?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).{6,20})").unwrap();
    }
    RE.is_match(pw)
}

pub fn check_name(pw: &String) -> bool {
    lazy_static! {//todo evaluate the name check constrain too
        static ref RE: Regex = Regex::new(r"/(^[a-zA-Z][a-zA-Z\s]{0,20}[a-zA-Z]$)/").unwrap();
    }
    RE.is_match(pw)
}

//=========================================================================================================
