use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceIds {
    #[serde(rename = "uuid")]
    pub aci: Uuid,
    /// `None` for an account without a phone number.
    #[serde(default)]
    pub pni: Option<Uuid>,
}

impl ServiceIds {
    pub fn aci(&self) -> libsignal_protocol::Aci {
        libsignal_protocol::Aci::from_uuid_bytes(self.aci.into_bytes())
    }

    /// `None` for an account without a phone number.
    pub fn pni(&self) -> Option<libsignal_protocol::Pni> {
        self.pni.map(|pni| {
            libsignal_protocol::Pni::from_uuid_bytes(pni.into_bytes())
        })
    }
}

impl fmt::Display for ServiceIds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "aci={}", self.aci)?;
        match self.pni {
            Some(pni) => write!(f, " pni={pni}"),
            None => f.write_str(" pni=none"),
        }
    }
}
