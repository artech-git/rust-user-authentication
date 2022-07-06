use std::{collections::hash_map::DefaultHasher, hash::{Hash, Hasher}};


use jsonwebtoken::{Header, encode};
use regex::Regex;

use crate::obj::{Claims, KEYS, AuthError, KEY_MAP};


//TODO validate user input of password
//TODO validate user input of email string
//TODO validate user input of name


//TODO apply the improved hashing algorithm for the given function
pub fn get_hash(client_secret: &String) -> String {

    let mut hasher = DefaultHasher::new();

    client_secret.hash(&mut hasher);

    let hash = hasher.finish();
    
    hash.to_string()

}


pub fn generate_claim(sub: String, uid: String ) -> Result<String, AuthError> {
    
    let exp = match KEY_MAP.get(&"token_validity".to_string()){
        Some(token) => {
            match token.to_owned().parse::<usize>() {
                Ok(v) => v,
                Err(v) => {
                    tracing::log::error!("value must contain only numbers: {}", v);
                    panic!();
                }
            }
        }
        None => {
            tracing::log::error!("please insert token_validity parameter");
            panic!();
        }
    };

    let claims = Claims {
        sub: sub,
        user_uid: uid,
        // Mandatory expiry time as UTC timestamp
        exp: exp,  
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