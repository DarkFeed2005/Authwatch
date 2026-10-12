//! AuthWatch core: everything except the user interfaces.

pub mod alert;
pub mod config;
pub mod detector;
pub mod discord;
pub mod enrich;
pub mod event;
pub mod mitre;
pub mod monitor;
pub mod parser;
pub mod tail;
pub mod throttle;

pub use alert::{Alert, AlertKind, Severity};
pub use config::Config;
pub use monitor::{spawn, AlertRecord, Delivery, LogEntry, MonitorHandle, Stats, UiEvent};
