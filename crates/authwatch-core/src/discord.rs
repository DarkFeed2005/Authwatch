//! Discord webhook notifier (rich embeds).
//!
//! Security notes:
//! * Usernames, commands and log lines are attacker-controlled. Everything is
//!   markdown-escaped or placed in code blocks, and `allowed_mentions` is empty so
//!   a username like `@everyone` can never ping anyone.
//! * The webhook URL is a secret; reqwest errors are stripped of the URL before
//!   they are surfaced or logged.

use crate::alert::{Alert, Severity};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::time::Duration;

pub struct DiscordNotifier {
    client: reqwest::Client,
    url: String,
    bot_name: String,
}

impl DiscordNotifier {
    pub fn new(webhook_url: String, bot_name: String) -> Result<Self> {
        let url = webhook_url.trim().to_string();
        if !url.starts_with("https://") || !url.contains("/api/webhooks/") {
            bail!("discord.webhook_url must look like https://discord.com/api/webhooks/<id>/<token>");
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("authwatch/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { client, url, bot_name })
    }

    /// Send one alert, honouring Discord's rate-limit responses (HTTP 429).
    pub async fn send(&self, alert: &Alert, suppressed: u32) -> Result<()> {
        const MAX_ATTEMPTS: u32 = 4;
        let payload = build_payload(alert, suppressed, &self.bot_name);

        for attempt in 1..=MAX_ATTEMPTS {
            let last = attempt == MAX_ATTEMPTS;
            match self.client.post(&self.url).json(&payload).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) if resp.status().as_u16() == 429 => {
                    let header = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<f64>().ok());
                    let body: Value = resp.json().await.unwrap_or(Value::Null);
                    let wait = header.or_else(|| body["retry_after"].as_f64()).unwrap_or(2.0);
                    if last {
                        bail!("Discord rate limit still active after {MAX_ATTEMPTS} attempts");
                    }
                    tokio::time::sleep(Duration::from_secs_f64(wait.clamp(0.5, 30.0))).await;
                }
                Ok(resp) if resp.status().is_server_error() && !last => {
                    tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    bail!("Discord rejected the webhook ({status}): {}", truncate(&body, 200));
                }
                Err(e) if !last => {
                    tracing::debug!("discord send attempt {attempt} failed: {}", e.without_url());
                    tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                }
                Err(e) => return Err(anyhow!("Discord request failed: {}", e.without_url())),
            }
        }
        unreachable!()
    }
}

fn color(s: Severity) -> u32 {
    match s {
        Severity::Low => 0x3498db,
        Severity::Medium => 0xf1c40f,
        Severity::High => 0xe67e22,
        Severity::Critical => 0xe74c3c,
    }
}

fn emoji(s: Severity) -> &'static str {
    match s {
        Severity::Low => "ℹ️",
        Severity::Medium => "⚠️",
        Severity::High => "🚨",
        Severity::Critical => "🔥",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Escape Discord markdown and neutralise mention syntax in untrusted text.
fn escape_md(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '*' | '_' | '~' | '|' | '`' | '>' | '#' | '[' | ']' | '(' | ')' => {
                out.push('\\');
                out.push(c);
            }
            '@' => out.push_str("@\u{200b}"),
            c if c.is_control() && c != '\n' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Inline code span that cannot be broken out of.
fn code(s: &str) -> String {
    format!("`{}`", truncate(&s.replace('`', "'").replace('\n', " "), 200))
}

/// Fenced block that cannot be broken out of.
fn block(s: &str, max: usize) -> String {
    format!("```\n{}\n```", truncate(&s.replace('`', "'"), max))
}

fn field(name: &str, value: String, inline: bool) -> Value {
    json!({ "name": name, "value": truncate(&value, 1024), "inline": inline })
}

/// Pure function (no I/O) so the exact payload can be unit-tested.
pub fn build_payload(alert: &Alert, suppressed: u32, bot_name: &str) -> Value {
    let tech = alert.kind.technique();
    let ts = alert.timestamp;

    let mut fields = vec![
        field("Alert Type", escape_md(alert.kind.label()), true),
        field("Severity", alert.severity.label().to_string(), true),
        field(
            "MITRE ATT&CK",
            format!("[{}]({})\n{} · {}", tech.id, tech.url(), escape_md(tech.name), tech.tactic),
            true,
        ),
        field("Source IP", alert.src_ip.map_or("n/a (local event)".into(), |ip| code(&ip.to_string())), true),
        field("Username", alert.username.as_deref().map_or("n/a".into(), code), true),
        field(
            "Timestamp",
            format!("{} UTC\n<t:{}:R>", ts.format("%Y-%m-%d %H:%M:%S"), ts.timestamp()),
            true,
        ),
        field("Details", block(&alert.details, 900), false),
    ];

    if let Some(rep) = &alert.reputation {
        let mut line = format!("**{}%** abuse confidence · {} reports", rep.score, rep.total_reports);
        let meta: Vec<String> = [&rep.country_code, &rep.isp, &rep.usage_type]
            .into_iter()
            .flatten()
            .map(|s| escape_md(s))
            .collect();
        if !meta.is_empty() {
            line.push_str(&format!("\n{}", meta.join(" · ")));
        }
        fields.push(field(&format!("{} reputation", rep.source), line, false));
    }
    if let Some(ev) = &alert.evidence {
        fields.push(field("Evidence", block(ev, 900), false));
    }
    if suppressed > 0 {
        fields.push(field(
            "Suppressed duplicates",
            format!("{suppressed} similar alert(s) were suppressed since the last notification."),
            false,
        ));
    }

    json!({
        "username": bot_name,
        "allowed_mentions": { "parse": [] },
        "embeds": [{
            "title": truncate(&format!("{} {} — {}", emoji(alert.severity), alert.severity.label(), alert.kind.label()), 250),
            "description": truncate(&escape_md(&alert.summary), 1500),
            "color": color(alert.severity),
            "timestamp": ts.to_rfc3339(),
            "fields": fields,
            "footer": { "text": format!("AuthWatch · host: {}", truncate(&alert.host, 60)) },
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::AlertKind;
    use chrono::{TimeZone, Utc};

    fn sample() -> Alert {
        Alert {
            timestamp: Utc.with_ymd_and_hms(2026, 10, 12, 10, 0, 0).unwrap(),
            host: "web01".into(),
            kind: AlertKind::BruteForce,
            severity: Severity::High,
            src_ip: Some("203.0.113.9".parse().unwrap()),
            username: Some("@everyone`injected".into()),
            summary: "5 failed logins from 203.0.113.9 within 60s.".into(),
            details: "details with ``` fence".into(),
            evidence: Some("raw line".into()),
            dedupe_key: "brute:203.0.113.9".into(),
            reputation: None,
        }
    }

    #[test]
    fn payload_has_required_fields_and_no_mentions() {
        let p = build_payload(&sample(), 3, "AuthWatch");
        assert_eq!(p["allowed_mentions"]["parse"].as_array().unwrap().len(), 0);
        let embed = &p["embeds"][0];
        let names: Vec<&str> = embed["fields"].as_array().unwrap().iter().map(|f| f["name"].as_str().unwrap()).collect();
        for want in ["Alert Type", "MITRE ATT&CK", "Source IP", "Username", "Timestamp", "Suppressed duplicates"] {
            assert!(names.contains(&want), "missing field {want}");
        }
        let mitre = embed["fields"][2]["value"].as_str().unwrap();
        assert!(mitre.contains("T1110.001") && mitre.contains("attack.mitre.org/techniques/T1110/001/"));
    }

    #[test]
    fn untrusted_text_cannot_break_out() {
        let p = build_payload(&sample(), 0, "AuthWatch");
        let user = p["embeds"][0]["fields"][4]["value"].as_str().unwrap();
        assert_eq!(user.matches('`').count(), 2); // only our own delimiters
        let details = p["embeds"][0]["fields"][6]["value"].as_str().unwrap();
        assert_eq!(details.matches("```").count(), 2);
    }

    #[test]
    fn webhook_url_validation() {
        assert!(DiscordNotifier::new("http://example.com".into(), "x".into()).is_err());
        assert!(DiscordNotifier::new("https://discord.com/api/webhooks/1/abc".into(), "x".into()).is_ok());
    }
}
