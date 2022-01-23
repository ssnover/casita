use openssl::ssl::SslStream;
use rand::rngs::OsRng;
use rsa::{pkcs8::{ToPrivateKey, ToPublicKey}, RsaPrivateKey, RsaPublicKey};
use std::io::{Read, Write};
use std::net::TcpStream;

mod lap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_name = "caseta.key";
    let cert_name = "caseta.crt";
    let ca_cert_name = "caseta-bridge.crt";

    let mut rng = OsRng;
    let public_exponent = 65537u32.into();
    let private_key = RsaPrivateKey::new_with_exp(&mut rng, 2048, &public_exponent).unwrap();
    let mut key_file = std::fs::File::create(key_name)?;
    let private_key_pem = private_key.to_pkcs8_pem().unwrap();
    let private_key_pem_bytes = private_key_pem.as_bytes();
    let public_key = RsaPublicKey::from(&private_key);
    let public_key_pem = public_key.to_public_key_pem().unwrap();
    let public_key_pem_bytes = public_key_pem.as_bytes();
    key_file.write(private_key_pem_bytes)?;

    let lap_ca = openssl::x509::X509::from_pem(lap::LAP_CA.as_bytes()).unwrap();
    let lap_cert = openssl::x509::X509::from_pem(lap::LAP_CERT.as_bytes()).unwrap();
    let lap_key = openssl::pkey::PKey::from_rsa(
        openssl::rsa::Rsa::private_key_from_pem(lap::LAP_KEY.as_bytes()).unwrap(),
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

    println!(
        "Connected to bridge. Press and release the small black button on the back of the bridge"
    );

    'wait: loop {
        if let Ok(msg) = serde_json::from_value::<lap::Message>(socket.read_message()?) {
            if msg.Header.ContentType.starts_with("status;") {
                if let Ok(body) = serde_json::from_value::<lap::ReportButtonPressBody>(msg.Body) {
                    if body
                        .Status
                        .Permissions
                        .contains(&lap::Permissions::PhysicalAccess)
                    {
                        println!("Demonstrated physical access!");
                        break 'wait;
                    }
                }
            }
        }
    }

    let mut name_builder = openssl::x509::X509Name::builder().unwrap();
    name_builder.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "hacky.rs").unwrap();
    let name = name_builder.build();
    let mut csr = openssl::x509::X509ReqBuilder::new().unwrap();
    csr.set_subject_name(name.as_ref()).unwrap();
    let rsa = openssl::rsa::Rsa::private_key_from_pem(private_key_pem_bytes).unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let rsa_public = openssl::rsa::Rsa::public_key_from_pem(public_key_pem_bytes).unwrap();
    let pkey_public = openssl::pkey::PKey::from_rsa(rsa_public).unwrap();
    csr.sign(&pkey, openssl::hash::MessageDigest::sha256())
        .unwrap();
    csr.set_pubkey(&pkey_public).unwrap();
    let csr_text = csr
        .build()
        .to_pem()
        .unwrap();
    let csr_text: String = std::str::from_utf8(&csr_text).to_owned().unwrap().to_owned();
    
    let request = serde_json::json!({
        "Header": {
            "RequestType": "Execute",
            "Url": "/pair",
            "ClientTag": "get-cert",
        },
        "Body": {
            "CommandType": "CSR",
            "Parameters": {
                "CSR": csr_text,
                "DisplayName": "hack.rs",
                "DeviceUID": "000000000000",
                "Role": "Admin",
            },
        },
    });
    socket.write_message(&request).unwrap();
    loop {
        if let Ok(msg) = serde_json::from_value::<lap::Message>(socket.read_message()?) {
            if msg.Header.ClientTag == Some("get-cert".to_owned()) {
                if let Ok(signing_result) = serde_json::from_value::<lap::SigningResultResponse>(msg.Body) {
                    let cert = signing_result.SigningResult.Certificate;
                    let root_cert = signing_result.SigningResult.RootCertificate;
                    let mut cert_file = std::fs::File::create(cert_name)?;
                    cert_file.write(cert.as_bytes())?;
                    let mut ca_cert_file = std::fs::File::create(ca_cert_name)?;
                    ca_cert_file.write(root_cert.as_bytes())?;
                }
                break;
            }
        }
    }

    Ok(())
}

struct JsonSocket {
    stream: SslStream<TcpStream>,
}

impl JsonSocket {
    pub fn new(stream: SslStream<TcpStream>) -> Self {
        Self { stream }
    }

    pub fn read_message(&mut self) -> Result<serde_json::Value, std::io::Error> {
        let mut intermediate_read_buffer = [0u8; 1024];
        let mut final_read_buffer = vec![];
        let mut full_message_read = false;
        while !full_message_read {
            let bytes_read = self.stream.read(&mut intermediate_read_buffer)?;
            final_read_buffer.extend_from_slice(&intermediate_read_buffer[..bytes_read]);
            if final_read_buffer[final_read_buffer.len() - 1] == b'\n'
                && final_read_buffer[final_read_buffer.len() - 2] == b'\r'
            {
                full_message_read = true;
            }
        }

        Ok(serde_json::from_slice(&final_read_buffer[..]).unwrap())
    }

    pub fn write_message(&mut self, message: &serde_json::Value) -> Result<(), std::io::Error> {
        self.stream.write(&message.to_string().as_bytes())?;
        self.stream.write(&[b'\r', b'\n'])?;
        Ok(())
    }
}
