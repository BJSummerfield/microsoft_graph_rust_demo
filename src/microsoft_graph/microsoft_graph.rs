use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

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
struct KeySecret {
    r#use: String,
    k: String,
    nbf: Option<i64>,
    exp: Option<i64>,
}

impl KeySecret {
    fn new() -> Self {
        KeySecret {
            r#use: "sig".to_string(),
            k: "My Super Secret".to_string(),
            nbf: Some(1702532556),
            exp: Some(1702532556),
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_on: String,
}

#[derive(Debug, Error)]
pub enum MicrosoftGraphError {
    #[error("environment variable error: {0}")]
    EnvVarError(#[from] env::VarError),
    #[error("request error: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("JSON deserialization error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("parse int error: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("HTTP response error: {status} {body}")]
    HttpResponseError {
        status: reqwest::StatusCode,
        body: String,
    },
}

pub struct MicrosoftGraph {
    pub access_token: String,
    pub expires_on: u64,
    client: Client,
}

impl MicrosoftGraph {
    pub async fn new() -> Result<Self, MicrosoftGraphError> {
        let mut new_instance = MicrosoftGraph {
            access_token: String::new(),
            expires_on: 0,
            client: Client::new(),
        };

        new_instance.get_token().await?;

        Ok(new_instance)
    }

    pub async fn create_key_set(&self, key_id: &str) -> Result<KeySet, MicrosoftGraphError> {
        let key_set = KeySet::new(key_id);
        let key_set_json = serde_json::to_string(&key_set)?;
        println!("Key Set JSON: {}", key_set_json);

        let response = self
            .client
            .post(format!(
                "https://graph.microsoft.com/beta/trustFramework/keySets"
            ))
            .bearer_auth(&self.access_token)
            .header("Content-Type", "application/json")
            .body(key_set_json)
            .send()
            .await
            .map_err(MicrosoftGraphError::RequestError)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            eprintln!("HTTP Error: {}\n{}", status, error_body);
            return Err(MicrosoftGraphError::HttpResponseError {
                status,
                body: error_body,
            });
        }
        let key_response: KeySet = response
            .json()
            .await
            .map_err(MicrosoftGraphError::RequestError)?;

        Ok(key_response)
    }

    pub async fn upload_secret(&self, key_id: &str) -> Result<Key, MicrosoftGraphError> {
        let key_secret = KeySecret::new();
        let key_secret_json = serde_json::to_string(&key_secret)?;
        let response = self
            .client
            .post(format!(
                "https://graph.microsoft.com/beta/trustFramework/keySets/{key_id}/uploadSecret"
            ))
            .bearer_auth(&self.access_token)
            .header("Content-Type", "application/json")
            .body(key_secret_json)
            .send()
            .await
            .map_err(MicrosoftGraphError::RequestError)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            eprintln!("HTTP Error: {}\n{}", status, error_body);
            return Err(MicrosoftGraphError::HttpResponseError {
                status,
                body: error_body,
            });
        }
        let key_response: Key = response
            .json()
            .await
            .map_err(MicrosoftGraphError::RequestError)?;

        Ok(key_response)
    }

    //Takes in a keyset ID from https://graph.microsoft.com/beta/trustFramework/keySets/{id}
    pub async fn get_key_set(&self, key_id: &str) -> Result<KeySet, MicrosoftGraphError> {
        let response = self
            .client
            .get(format!(
                "{}/{}",
                "https://graph.microsoft.com/beta/trustFramework/keySets", key_id
            ))
            .bearer_auth(&self.access_token)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(MicrosoftGraphError::RequestError)?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response.text().await.unwrap_or_default();
            eprintln!("HTTP Error: {}\n{}", status, error_body);
            return Err(MicrosoftGraphError::HttpResponseError {
                status,
                body: error_body,
            });
        }

        let key_response: KeySet = response
            .json()
            .await
            .map_err(MicrosoftGraphError::RequestError)?;

        Ok(key_response)
    }

    async fn refresh_token(&mut self) -> Result<(), MicrosoftGraphError> {
        let client_id = env::var("CLIENT_ID")?;
        let client_secret = env::var("CLIENT_SECRET")?;
        let tenant = env::var("TENANT")?;
        let login_url = env::var("LOGIN_URL")?;
        let resource = env::var("RESOURCE")?;

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("resource", &resource),
        ];

        let token_response = self
            .client
            .post(&format!(
                "{}/{}/oauth2/token?api-version=1.0",
                login_url, tenant
            ))
            .form(&params)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await?;

        if token_response.status().is_success() {
            let token: TokenResponse = token_response.json().await?;
            self.access_token = token.access_token;
            self.expires_on = token.expires_on.parse()?;
            Ok(())
        } else {
            Err(MicrosoftGraphError::RequestError(
                token_response.error_for_status().err().unwrap(),
            ))
        }
    }

    fn has_token_expired(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        current_time >= self.expires_on
    }

    pub async fn get_token(&mut self) -> Result<String, MicrosoftGraphError> {
        if self.has_token_expired() {
            self.refresh_token().await?;
        }

        Ok(self.access_token.clone())
    }
}
