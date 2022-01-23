#![allow(non_snake_case)]

use serde::Deserialize;

pub mod certs;
pub use certs::*;

#[derive(Deserialize)]
pub struct Message {
    pub Header: Header,
    pub Body: serde_json::Value,
}

#[derive(Deserialize)]
pub struct Header {
    pub ContentType: String,
    pub StatusCode: String,
    pub ClientTag: Option<String>,
}

#[derive(Copy, Clone, Deserialize, PartialEq)]
pub enum Permissions {
    Public,
    PhysicalAccess,
}

#[derive(Deserialize)]
pub struct PermissionsStatus {
    pub Permissions: Vec<Permissions>,
}

#[derive(Deserialize)]
pub struct ReportButtonPressBody {
    pub Status: PermissionsStatus,
}

#[derive(Deserialize)]
pub struct SigningResultResponse {
    pub SigningResult: Certificates,
}

#[derive(Deserialize)]
pub struct Certificates {
    pub Certificate: String,
    pub RootCertificate: String,
}
