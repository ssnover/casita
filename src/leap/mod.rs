use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Message {
    pub communique_type: CommuniqueType,
    pub header: Header,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

impl Message {
    pub fn new(communique_type: CommuniqueType, url: String) -> Self {
        Self {
            communique_type,
            header: Header::new(url).with_client_tag("casita".to_owned()),
            body: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum CommuniqueType {
    ReadRequest,
    ReadResponse,
    SubscribeRequest,
    SubscribeResponse,
    UpdateResponse,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Header {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_tag: Option<String>,
}

impl Header {
    pub fn new(url: String) -> Self {
        Header {
            url,
            status_code: None,
            client_tag: None,
        }
    }

    pub fn with_client_tag(mut self, tag: String) -> Self {
        self.client_tag = Some(tag);
        self
    }
}
