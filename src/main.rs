use dotenv::dotenv;

mod microsoft_graph;
use microsoft_graph::MicrosoftGraph;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let microsoft_graph = MicrosoftGraph::new()
        .await
        .expect("Failed to create MicrosoftGraph instance");

    let new_key_set = microsoft_graph
        .create_key_set("B2C_1A_TestKey1")
        .await
        .expect("Failed to create key");

    println!("New Key Set: {:?}", new_key_set);

    let new_secret = microsoft_graph
        .upload_secret("B2C_1A_TestKey1")
        .await
        .expect("Failed to upload secret");

    println!("New Secret: {:?}", new_secret);

    let fetched_key = microsoft_graph
        .get_key_set("B2C_1A_TestKey1")
        .await
        .expect("Failed to get key");

    println!("Fetched Key: {:?}", fetched_key);
}
