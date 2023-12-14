use crate::microsoft_graph::policy_keys::models::*;
use crate::microsoft_graph::{MicrosoftGraph, MicrosoftGraphError};

pub struct PolicyKey {
    base_url: String,
    graph: MicrosoftGraph,
}

impl PolicyKey {
    pub fn new(graph: MicrosoftGraph) -> Self {
        PolicyKey {
            base_url: "https://graph.microsoft.com/beta/trustFramework/keySets".to_string(),
            graph,
        }
    }

    async fn send_request<T: for<'de> serde::Deserialize<'de>>(
        &mut self,
        url: String,
        method: reqwest::Method,
        body: Option<String>,
    ) -> Result<T, MicrosoftGraphError> {
        let client = &self.graph.client;
        let request_builder = client
            .request(method, url)
            .bearer_auth(self.graph.get_token().await?)
            .header("Content-Type", "application/json");

        let request = match body {
            Some(json_body) => request_builder.body(json_body),
            None => request_builder,
        };

        let response = request
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

        response
            .json()
            .await
            .map_err(MicrosoftGraphError::RequestError)
    }

    pub async fn create_key_set(&mut self, key_id: &str) -> Result<KeySet, MicrosoftGraphError> {
        let key_set = KeySet::new(key_id);
        let key_set_json = serde_json::to_string(&key_set)?;

        self.send_request(
            self.base_url.to_string(),
            reqwest::Method::POST,
            Some(key_set_json),
        )
        .await
    }

    pub async fn upload_secret(&mut self, key_id: &str) -> Result<Key, MicrosoftGraphError> {
        let key_secret = KeySecret::new();
        let key_secret_json = serde_json::to_string(&key_secret)?;

        self.send_request(
            format!("{}/{}/uploadSecret", self.base_url, key_id),
            reqwest::Method::POST,
            Some(key_secret_json),
        )
        .await
    }

    pub async fn get_key_set(&mut self, key_id: &str) -> Result<KeySet, MicrosoftGraphError> {
        self.send_request(
            format!("{}/{}", self.base_url, key_id),
            reqwest::Method::GET,
            None,
        )
        .await
    }
}
