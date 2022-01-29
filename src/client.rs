use async_channel::{Receiver, Sender};
use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{Ssl, SslContext, SslContextBuilder, SslMethod},
    x509::X509,
};
use serde_json::{json, Value};
use std::io;
use std::{fs::File, io::Read};
use std::{net::SocketAddr, path::PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

type WriteStream = WriteHalf<SslStream<TcpStream>>;
type ReadStream = ReadHalf<SslStream<TcpStream>>;

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
    write_channel: Option<Sender<Value>>,
    read_channel: Option<Receiver<Value>>,
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
            write_channel: None,
            read_channel: None,
        }
    }

    pub async fn connect(&mut self) {
        let ssl = Ssl::new(&self.ssl_context).unwrap();
        let stream = TcpStream::connect(self.socket_addr).await.unwrap();
        let mut stream = SslStream::new(ssl, stream).unwrap();
        std::pin::Pin::new(&mut stream).connect().await.unwrap();
        let (read, write) = tokio::io::split(stream);
        let (write_tx, write_rx) = async_channel::bounded(10);
        let (read_tx, read_rx) = async_channel::bounded(10);
        let (timeout_tx, timeout_rx) = async_channel::bounded(10);

        tokio::spawn(Client::write_context(write, write_rx, timeout_rx.clone()));
        tokio::spawn(Client::keep_alive_context(write_tx.clone(), timeout_rx));
        tokio::spawn(Client::read_context(read, read_tx, timeout_tx));

        self.write_channel = Some(write_tx);
        self.read_channel = Some(read_rx);
    }

    pub fn disconnect(&mut self) {
        self.write_channel = None;
        self.read_channel = None;
    }

    pub fn is_connected(&self) -> bool {
        match (&self.write_channel, &self.read_channel) {
            (Some(w), Some(r)) => !w.is_closed() || !r.is_closed(),
            _ => false,
        }
    }

    pub async fn send(&mut self, msg: Value) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(tx) = self.write_channel.as_mut() {
            tx.send(msg).await?;
            Ok(())
        } else {
            Err(Box::<io::Error>::new(io::ErrorKind::NotConnected.into()))
        }
    }

    pub async fn read_message(&mut self) -> io::Result<Value> {
        if let Some(rx) = self.read_channel.as_mut() {
            if let Ok(msg) = rx.recv().await {
                Ok(msg)
            } else {
                Err(io::ErrorKind::NotConnected.into())
            }
        } else {
            Err(io::ErrorKind::NotConnected.into())
        }
    }

    async fn read_context(mut stream: ReadStream, tx: Sender<Value>, timeout_tx: Sender<()>) {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(60)) => {
                    log::error!("Connection to Lutron Caseta timed out");
                    let _ = timeout_tx.send(()).await;
                    break;
                },
                msg = Client::read_from_stream(&mut stream) => {
                    let msg = msg.unwrap();
                    tx.send(msg).await.unwrap();
                }
            }
        }
    }

    async fn read_from_stream(stream: &mut ReadStream) -> io::Result<Value> {
        let mut intermediate_read_buffer = [0u8; 1024];
        let mut final_read_buffer = vec![];
        loop {
            let bytes_read = stream.read(&mut intermediate_read_buffer).await?;
            final_read_buffer.extend_from_slice(&intermediate_read_buffer[..bytes_read]);
            if let Some(newline_idx) = find_newline_in_bytes(&final_read_buffer) {
                return Ok(serde_json::from_slice(&final_read_buffer[..newline_idx]).unwrap());
            }
        }
    }

    async fn write_context(mut stream: WriteStream, rx: Receiver<Value>, timeout_rx: Receiver<()>) {
        loop {
            tokio::select! {
                _ = timeout_rx.recv() => {
                    break;
                },
                msg = rx.recv() => {
                    if let Ok(msg) = msg {
                        Client::write_to_stream(&mut stream, msg).await.unwrap();
                    }
                }
            }
        }
    }

    async fn write_to_stream(stream: &mut WriteStream, msg: Value) -> io::Result<()> {
        let _bytes_written = stream
            .write(&[msg.to_string().as_bytes(), &[b'\r', b'\n']].concat())
            .await?;
        Ok(())
    }

    async fn keep_alive_context(tx: Sender<Value>, timeout_rx: Receiver<()>) {
        loop {
            tokio::select! {
                _ = timeout_rx.recv() => {
                    break;
                },
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                    let msg = json!({
                        "CommuniqueType": "ReadRequest",
                        "Header": {
                            "Url": "/server/1/status/ping",
                        }
                    });
                    let _ = tx.send(msg).await;
                }
            }
        }
    }
}

fn find_newline_in_bytes(bytes: &[u8]) -> Option<usize> {
    for (idx, &byte) in bytes.iter().enumerate() {
        if byte == b'\r' && bytes.len() != idx + 1 && bytes[idx + 1] == b'\n' {
            return Some(idx);
        }
    }

    None
}
