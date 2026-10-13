//! Normalised events produced by the parser and consumed by the detector.

use chrono::{DateTime, Utc};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    FailedLogin { user: String, ip: IpAddr, invalid_user: bool },
    SuccessfulLogin { user: String, ip: IpAddr, method: String },
    UserCreated { user: String, uid: u32 },
    Sudo { invoker: String, target: String, command: String, tty: Option<String>, pwd: String },
}

impl EventKind {
    /// Short label used by the GUI to tag parsed lines.
    pub fn label(&self) -> &'static str {
        match self {
            EventKind::FailedLogin { .. } => "FAILED",
            EventKind::SuccessfulLogin { .. } => "ACCEPTED",
            EventKind::UserCreated { .. } => "USERADD",
            EventKind::Sudo { .. } => "SUDO",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthEvent {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub kind: EventKind,
    pub raw: String,
}
