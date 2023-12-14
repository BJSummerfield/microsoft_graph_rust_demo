use reqwest::Client;
use serde::Deserialize;
use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

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
    pub client: Client,
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
