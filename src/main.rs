use dotenv::dotenv;

mod microsoft_graph;
use microsoft_graph::{MicrosoftGraph, PolicyKey};

#[tokio::main]
async fn main() {
    dotenv().ok();
    let key_name = "B2C_1A_MSASecret";

    let microsoft_graph = MicrosoftGraph::new()
        .await
        .expect("Failed to create MicrosoftGraph instance");

    let mut policy_key = PolicyKey::new(microsoft_graph);

    let new_key_set = policy_key
        .create_key_set(&key_name)
        .await
        .expect("Failed to create key");

    println!("New Key Set: {:?}", new_key_set);

    let new_secret = policy_key
        .upload_secret(&key_name)
        .await
        .expect("Failed to upload secret");

    println!("New Secret: {:?}", new_secret);

    let fetched_key = policy_key
        .get_key_set(key_name)
        .await
        .expect("Failed to get key");

    println!("Fetched Key: {:?}", fetched_key);
}
