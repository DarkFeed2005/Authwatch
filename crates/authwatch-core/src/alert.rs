//! Alert model shared by the detector, notifier, throttle and GUI.

use crate::enrich::IpReputation;
use crate::mitre::{self, Technique};
use chrono::{DateTime, Utc};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertKind {
    BruteForce,
    PasswordSpray,
    CompromisedAccount,
    NewUserAccount,
    SuspiciousSudo,
}

impl AlertKind {
    pub fn label(&self) -> &'static str {
        match self {
            AlertKind::BruteForce => "SSH Brute Force",
            AlertKind::PasswordSpray => "Password Spraying",
            AlertKind::CompromisedAccount => "Possible Account Compromise",
            AlertKind::NewUserAccount => "New User Account Created",
            AlertKind::SuspiciousSudo => "Suspicious Sudo Command",
        }
    }

    pub fn slug(&self) -> &'static str {
        match self {
            AlertKind::BruteForce => "brute",
            AlertKind::PasswordSpray => "spray",
            AlertKind::CompromisedAccount => "compromised",
            AlertKind::NewUserAccount => "newuser",
            AlertKind::SuspiciousSudo => "sudo",
        }
    }

    pub fn technique(&self) -> &'static Technique {
        match self {
            AlertKind::BruteForce => &mitre::T1110_001,
            AlertKind::PasswordSpray => &mitre::T1110_003,
            AlertKind::CompromisedAccount => &mitre::T1078,
            AlertKind::NewUserAccount => &mitre::T1136_001,
            AlertKind::SuspiciousSudo => &mitre::T1548_003,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub kind: AlertKind,
    pub severity: Severity,
    pub src_ip: Option<IpAddr>,
    pub username: Option<String>,
    pub summary: String,
    pub details: String,
    /// The raw log line that triggered the alert.
    pub evidence: Option<String>,
    /// Alerts with the same key are considered duplicates by the throttle and GUI.
    pub dedupe_key: String,
    /// Filled in later by an [`IpEnricher`](crate::enrich::IpEnricher).
    pub reputation: Option<IpReputation>,
}
