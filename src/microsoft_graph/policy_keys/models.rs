use serde::{Deserialize, Serialize};

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
        KeySecret {
            r#use: "sig".to_string(),
            k: "My Super Secret".to_string(),
            nbf: Some(1702540440),
            exp: Some(1702540440),
        }
    }
}
