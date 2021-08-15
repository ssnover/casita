use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct Message {
    pub Header: Header,
    pub Body: serde_json::Value,
}

#[derive(Deserialize)]
pub struct Header {
    pub ContentType: String,
    pub StatusCode: String,
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