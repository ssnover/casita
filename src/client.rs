use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{Ssl, SslContext, SslContextBuilder, SslMethod},
    x509::X509,
};
use serde_json::json;
use std::{fs::File, io::Read};
use std::{
    net::{SocketAddr},
    path::PathBuf,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

pub struct Certs {
    leap_ca_cert: X509,
    leap_cert: X509,
    leap_key: PKey<Private>,
}

impl Certs {
    pub fn new(
        leap_ca_cert: PathBuf,
        leap_cert: PathBuf,
        leap_key: PathBuf,
    ) -> std::io::Result<Self> {
        let mut leap_ca_cert_file = File::open(leap_ca_cert)?;
        let mut ca_cert = Vec::new();
        leap_ca_cert_file.read_to_end(&mut ca_cert)?;
        let leap_ca = X509::from_pem(&ca_cert).unwrap();

        let mut leap_cert_file = File::open(leap_cert)?;
        let mut cert = Vec::new();
        leap_cert_file.read_to_end(&mut cert)?;
        let leap_cert = X509::from_pem(&cert).unwrap();

        let mut leap_key_file = File::open(leap_key)?;
        let mut key = Vec::new();
        leap_key_file.read_to_end(&mut key)?;
        let leap_key = PKey::from_rsa(Rsa::private_key_from_pem(&key).unwrap()).unwrap();

        Ok(Self {
            leap_ca_cert: leap_ca,
            leap_cert,
            leap_key,
        })
    }
}

pub struct Client {
    socket_addr: SocketAddr,
    ssl_context: SslContext,
    read_stream: Option<ReadHalf<SslStream<TcpStream>>>,
    write_channel: Option<async_channel::Sender<serde_json::Value>>,
}

impl Client {
    pub async fn new(certs: Certs, addr: String) -> Self {
        let mut context = SslContextBuilder::new(SslMethod::tls()).unwrap();
        context
            .cert_store_mut()
            .add_cert(certs.leap_ca_cert.clone())
            .unwrap();
        context.set_certificate(&certs.leap_cert).unwrap();
        context.set_private_key(&certs.leap_key).unwrap();
        let context = context.build();

        Self {
            socket_addr: addr.parse().unwrap(),
            ssl_context: context,
            read_stream: None,
            write_channel: None,
        }
    }

    pub async fn connect(&mut self) {
        let ssl = Ssl::new(&self.ssl_context).unwrap();
        let stream = TcpStream::connect(self.socket_addr).await.unwrap();
        let mut stream = SslStream::new(ssl, stream).unwrap();
        std::pin::Pin::new(&mut stream).connect().await.unwrap();
        let (read, write) = tokio::io::split(stream);
        let (tx, rx) = async_channel::bounded(10);
        self.read_stream = Some(read);
        self.write_channel = Some(tx);
        tokio::spawn(Client::write_context(write, rx));
    }

    pub async fn send(&mut self, msg: serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(tx) = self.write_channel.as_mut() {
            tx.send(msg).await?;
            Ok(())
        } else {
            Err(Box::<std::io::Error>::new(std::io::ErrorKind::NotConnected.into()))
        }
    }

    pub async fn read_message(&mut self) -> std::io::Result<serde_json::Value> {
        if let Some(stream) = self.read_stream.as_mut() {
            let mut intermediate_read_buffer = [0u8; 1024];
            let mut final_read_buffer = vec![];
            let mut full_message_read = false;
            while !full_message_read {
                let bytes_read = stream.read(&mut intermediate_read_buffer).await?;
                final_read_buffer.extend_from_slice(&intermediate_read_buffer[..bytes_read]);
                if final_read_buffer[final_read_buffer.len() - 1] == b'\n'
                    && final_read_buffer[final_read_buffer.len() - 2] == b'\r'
                {
                    full_message_read = true;
                }
            }

            Ok(serde_json::from_slice(&final_read_buffer[..]).unwrap())
        } else {
            Err(std::io::ErrorKind::NotConnected.into())
        }
    }

    async fn write_context(mut stream: WriteHalf<SslStream<TcpStream>>, rx: async_channel::Receiver<serde_json::Value>) {
        let ping_msg: serde_json::Value = json!({
            "CommuniqueType": "ReadRequest",
            "Header": {
                "Url": "/server/1/status/ping",
            }
        });

        loop {
            let next_msg = tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => { ping_msg.clone() },
                msg = rx.recv() => {
                    if let Ok(msg) = msg {
                        msg
                    } else {
                        break;
                    }
                }
            };
            stream.write(&next_msg.to_string().as_bytes()).await.unwrap();
            stream.write(&[b'\r', b'\n']).await.unwrap();
        }
    }
}
