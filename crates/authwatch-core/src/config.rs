//! Runtime configuration (TOML file + environment overrides for secrets).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::{net::IpAddr, path::{Path, PathBuf}};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Log file to follow. Use any file for testing.
    pub log_path: PathBuf,
    /// Start at the end of the file (live mode). `false` replays the whole file first.
    pub start_at_end: bool,
    pub poll_interval_ms: u64,
    pub detection: DetectionConfig,
    pub discord: DiscordConfig,
    pub abuseipdb: AbuseIpDbConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_path: PathBuf::from("/var/log/auth.log"),
            start_at_end: true,
            poll_interval_ms: 250,
            detection: DetectionConfig::default(),
            discord: DiscordConfig::default(),
            abuseipdb: AbuseIpDbConfig::default(),
        }
    }
}

impl Config {
    /// Load from an optional TOML file, then apply environment overrides.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut cfg = match path {
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("reading config {}", p.display()))?;
                toml::from_str::<Config>(&text)
                    .with_context(|| format!("parsing config {}", p.display()))?
            }
            None => Config::default(),
        };
        // Secrets are better kept out of files.
        if let Ok(v) = std::env::var("DISCORD_WEBHOOK_URL") {
            if !v.trim().is_empty() {
                cfg.discord.webhook_url = Some(v.trim().to_string());
            }
        }
        if let Ok(v) = std::env::var("ABUSEIPDB_API_KEY") {
            if !v.trim().is_empty() {
                cfg.abuseipdb.api_key = Some(v.trim().to_string());
            }
        }
        Ok(cfg)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DetectionConfig {
    /// Failed logins from one IP within `brute_force_window_secs` that trigger a brute-force alert.
    pub brute_force_threshold: usize,
    pub brute_force_window_secs: i64,
    /// Distinct usernames tried from one IP within `spray_window_secs`.
    pub spray_distinct_users: usize,
    pub spray_window_secs: i64,
    /// A success from an IP with at least this many failures in the window is suspicious.
    pub compromise_prior_failures: usize,
    pub compromise_window_secs: i64,
    /// Upper bound on per-IP state kept in memory.
    pub max_tracked_ips: usize,
    /// IPs that are never tracked (your own bastion, monitoring probes, ...).
    pub ignore_ips: Vec<IpAddr>,
    /// Sudo commands matching any of these regexes raise an alert.
    pub sudo_rules: Vec<SudoRule>,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            brute_force_threshold: 5,
            brute_force_window_secs: 60,
            spray_distinct_users: 4,
            spray_window_secs: 300,
            compromise_prior_failures: 3,
            compromise_window_secs: 600,
            max_tracked_ips: 10_000,
            ignore_ips: vec![],
            sudo_rules: default_sudo_rules(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SudoRule {
    pub name: String,
    pub pattern: String,
}

fn rule(name: &str, pattern: &str) -> SudoRule {
    SudoRule { name: name.into(), pattern: pattern.into() }
}

pub fn default_sudo_rules() -> Vec<SudoRule> {
    vec![
        rule("root shell", r"(^|/)(ba|z|da|k|c|tc)?sh(\s|$)"),
        rule("su to another user", r"(^|/)su(\s|$)"),
        rule("sudoers modification", r"\bvisudo\b|\bsudoedit\b|/etc/sudoers"),
        rule("credential file access", r"/etc/(shadow|gshadow)\b"),
        rule("setuid bit change", r"\bchmod\s+(-\w+\s+)*([ugoa]*\+s|[2467][0-7]{3})\b"),
        rule("reverse shell pattern", r"\b(nc|ncat|netcat)\b.*\s-e\b|/dev/tcp/"),
        rule("download and execute", r"\b(curl|wget)\b.*\|\s*(ba|z)?sh\b"),
        rule("account management", r"\b(useradd|adduser|usermod|userdel|passwd|chpasswd)\b"),
        rule("firewall tampering", r"\b(iptables|nft|ufw)\b.*(\s-F\b|flush|disable)"),
        rule("log tampering", r"\bhistory\s+-c\b|\bshred\b|\btruncate\b.*/var/log/|\brm\b.*/var/log/"),
        rule("immutable attribute", r"\bchattr\b"),
    ]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DiscordConfig {
    /// Webhook URL. Prefer the `DISCORD_WEBHOOK_URL` environment variable.
    pub webhook_url: Option<String>,
    pub bot_name: String,
    /// Same alert key (rule + IP/user) is sent at most once per cooldown.
    pub cooldown_secs: u64,
    /// Hard cap on messages per minute across all alerts.
    pub max_per_minute: usize,
}

impl Default for DiscordConfig {
    fn default() -> Self {
        Self {
            webhook_url: None,
            bot_name: "AuthWatch".into(),
            cooldown_secs: 900,
            max_per_minute: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AbuseIpDbConfig {
    pub enabled: bool,
    pub api_key: Option<String>,
    pub max_age_days: u32,
    pub cache_ttl_secs: u64,
}

impl Default for AbuseIpDbConfig {
    fn default() -> Self {
        Self { enabled: false, api_key: None, max_age_days: 90, cache_ttl_secs: 6 * 3600 }
    }
}
