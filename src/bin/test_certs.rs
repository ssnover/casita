use casita::{Certs, leap::{self, CommuniqueType}};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ip_addr = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("USAGE: get_certs IP_ADDR");
        std::process::exit(1);
    });
    
    let certs = Certs::new(
        PathBuf::from("./caseta-bridge.crt"),
        PathBuf::from("./caseta.crt"),
        PathBuf::from("./caseta.key"),
    )?;
    let mut client = casita::Client::new(certs, format!("{}:8081", ip_addr)).await;

    let ping_msg = leap::Message::new(CommuniqueType::ReadRequest, "/server/1/status/ping".to_owned());
    client.connect().await.unwrap();
    client.send(ping_msg).await.unwrap();

    let pong = client.read_message().await.unwrap();
    let pong = serde_json::from_value::<leap::Message>(pong).unwrap();
    println!("Response from Caseta Hub!");
    println!("{:?}", pong);

    Ok(())
}
