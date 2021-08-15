use std::io::{Read, Write};
use std::net::TcpStream;
use openssl::ssl::SslStream;

pub mod certs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_name = "caseta.key";
    let cert_name = "caseta.crt";
    let ca_cert_name = "caseta-bridge.crt";

    let lap_ca = openssl::x509::X509::from_pem(certs::LAP_CA.as_bytes()).unwrap();
    let lap_cert = openssl::x509::X509::from_pem(certs::LAP_CERT.as_bytes()).unwrap();
    let lap_key = openssl::pkey::PKey::from_rsa(
        openssl::rsa::Rsa::private_key_from_pem(certs::LAP_KEY.as_bytes()).unwrap(),
    )
    .unwrap();

    let mut context = openssl::ssl::SslContextBuilder::new(openssl::ssl::SslMethod::tls()).unwrap();
    context.cert_store_mut().add_cert(lap_ca).unwrap();
    context.set_certificate(&lap_cert).unwrap();
    context.set_private_key(&lap_key).unwrap();
    let context = context.build();
    let ssl = openssl::ssl::Ssl::new(&context).unwrap();

    let mut session_builder =
        openssl::ssl::SslStreamBuilder::new(ssl, TcpStream::connect("192.168.1.11:8083").unwrap());
    session_builder.set_connect_state();
    let tls_socket = session_builder.connect().unwrap();
    let mut socket = JsonSocket::new(tls_socket);
    
    println!("Connected to bridge. Press and release the small black button on the back of the bridge");
    println!("{}", socket.read_message()?);
    Ok(())
}

struct JsonSocket {
    stream: SslStream<TcpStream>,
}

impl JsonSocket {
    pub fn new(stream: SslStream<TcpStream>) -> Self {
        Self {
            stream
        }
    }

    pub fn read_message(&mut self) -> Result<serde_json::Value, std::io::Error> {
        let mut intermediate_read_buffer = [0u8; 1024];
        let mut final_read_buffer = vec![];
        let mut full_message_read = false;
        while !full_message_read {
            let bytes_read = self.stream.read(&mut intermediate_read_buffer)?;
            final_read_buffer.extend_from_slice(&intermediate_read_buffer[..bytes_read]);
            if final_read_buffer[final_read_buffer.len()-1] == b'\n' && final_read_buffer[final_read_buffer.len()-2] == b'\r' {
                full_message_read = true;
            }
        }

        Ok(serde_json::from_slice(&final_read_buffer[..]).unwrap())
    }

    pub fn write_message(&mut self, message: &serde_json::Value) -> Result<(), std::io::Error> {
        self.stream.write(&message.as_str().unwrap().as_bytes())?;
        self.stream.write(&[b'\r', b'\n'])?;
        Ok(())
    }
}