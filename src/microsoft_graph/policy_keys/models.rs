use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Serialize)]
pub struct KeySet {
    id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<Key>>,
}

impl KeySet {
    pub fn new(key_id: &str) -> Self {
        KeySet {
            id: key_id.to_string(),
            keys: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Key {
    r#use: String,
    kid: Option<String>,
    nbf: Option<i64>,
    exp: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct KeySecret {
    r#use: String,
    k: String,
    nbf: Option<i64>,
    exp: Option<i64>,
}

impl KeySecret {
    pub fn new() -> Self {
        if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
            let one_day = Duration::from_secs(60 * 60 * 24); // 24 hours in seconds
            let expiry_time = now + one_day;
            let current_time_seconds = now.as_secs();
            let expiry_time_seconds = expiry_time.as_secs();

            KeySecret {
                r#use: "sig".to_string(),
                k: "My Super Secret".to_string(),
                nbf: Some(current_time_seconds.try_into().unwrap()),
                exp: Some(expiry_time_seconds.try_into().unwrap()),
            }
        } else {
            panic!("System time before UNIX EPOCH!");
        }
    }
}
