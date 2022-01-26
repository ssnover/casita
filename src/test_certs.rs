use casita::Certs;
use serde_json::json;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let certs = Certs::new(
        PathBuf::from("./caseta-bridge.crt"),
        PathBuf::from("./caseta.crt"),
        PathBuf::from("./caseta.key"),
    )?;
    let mut client = casita::Client::new(certs, "192.168.1.11:8081".to_owned()).await;

    let ping_msg = json!({
        "CommuniqueType": "ReadRequest",
        "Header": {
            "Url": "/server/1/status/ping",
        }
    });
    client.connect().await;
    client.send(ping_msg).await.unwrap();

    let pong = client.read_message().await.unwrap();
    println!("Response from Caseta Hub!");
    println!("{}", pong.to_string());

    Ok(())
}
