use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{Ssl, SslContext, SslContextBuilder, SslMethod},
    x509::X509,
};
use std::{fs::File, io::Read};
use std::{
    net::{SocketAddr},
    path::PathBuf,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    stream: Option<SslStream<TcpStream>>,
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
            stream: None,
        }
    }

    pub async fn connect(&mut self) {
        let ssl = Ssl::new(&self.ssl_context).unwrap();
        let stream = TcpStream::connect(self.socket_addr).await.unwrap();
        let mut stream = SslStream::new(ssl, stream).unwrap();
        std::pin::Pin::new(&mut stream).connect().await.unwrap();
        self.stream = Some(stream);
    }

    pub async fn send_message(&mut self, msg: &serde_json::Value) -> std::io::Result<()> {
        if let Some(stream) = self.stream.as_mut() {
            stream.write(&msg.to_string().as_bytes()).await?;
            stream.write(&[b'\r', b'\n']).await?;
            Ok(())
        } else {
            Err(std::io::ErrorKind::NotConnected.into())
        }
    }

    pub async fn read_message(&mut self) -> std::io::Result<serde_json::Value> {
        if let Some(stream) = self.stream.as_mut() {
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
}
