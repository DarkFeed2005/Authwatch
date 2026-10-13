//! Wires everything together:
//!
//! ```text
//! tail task ──lines──▶ engine task ──alerts──▶ dispatcher task ──▶ Discord
//!                         │                         │
//!                         └────── UiEvent ──────────┴──▶ GUI / CLI
//! ```
//!
//! The GUI and CLI only ever see [`MonitorHandle`]; they never touch the pipeline.

use crate::{
    alert::Alert,
    config::Config,
    detector::Detector,
    discord::DiscordNotifier,
    enrich::{AbuseIpDbEnricher, CachedEnricher, IpEnricher, NoopEnricher},
    parser,
    tail::{tail_file, TailConfig},
    throttle::{AlertThrottle, Decision},
};
use anyhow::Result;
use chrono::{DateTime, Local, Utc};
use std::{
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub received: DateTime<Utc>,
    pub line: String,
    /// Set when the parser recognised the line as a security-relevant event.
    pub tag: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Sent,
    /// Swallowed by the cooldown / rate limit.
    Throttled,
    Failed(String),
    /// No webhook configured.
    Disabled,
}

#[derive(Debug, Clone)]
pub struct AlertRecord {
    pub alert: Alert,
    pub delivery: Delivery,
}

#[derive(Debug, Clone)]
pub enum UiEvent {
    Log(LogEntry),
    Alert(AlertRecord),
    /// Human-readable pipeline messages (errors, notices).
    Notice(String),
}

#[derive(Default)]
pub struct Stats {
    pub lines: AtomicU64,
    pub events: AtomicU64,
    pub alerts: AtomicU64,
    pub discord_sent: AtomicU64,
    pub discord_throttled: AtomicU64,
    pub discord_failed: AtomicU64,
    pub alerts_dropped: AtomicU64,
    pub tracked_ips: AtomicUsize,
}

pub struct MonitorInfo {
    pub log_path: String,
    pub discord_enabled: bool,
    pub enrichment: &'static str,
}

pub struct MonitorHandle {
    pub events: mpsc::Receiver<UiEvent>,
    pub stats: Arc<Stats>,
    pub info: MonitorInfo,
    cancel: CancellationToken,
}

impl MonitorHandle {
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

impl Drop for MonitorHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Start the pipeline. Must be called from inside a Tokio runtime context.
pub fn spawn(cfg: Config) -> Result<MonitorHandle> {
    let cancel = CancellationToken::new();
    let stats = Arc::new(Stats::default());
    let (ui_tx, ui_rx) = mpsc::channel::<UiEvent>(8192);
    let (line_tx, line_rx) = mpsc::channel::<String>(4096);
    let (alert_tx, alert_rx) = mpsc::channel::<Alert>(1024);

    let detector = Detector::new(cfg.detection.clone())?;

    let notifier = match cfg.discord.webhook_url.as_deref().filter(|u| !u.trim().is_empty()) {
        Some(url) => Some(DiscordNotifier::new(url.to_string(), cfg.discord.bot_name.clone())?),
        None => None,
    };

    let (enricher, enrichment): (Arc<dyn IpEnricher>, &'static str) =
        match (cfg.abuseipdb.enabled, cfg.abuseipdb.api_key.clone()) {
            (true, Some(key)) => {
                let inner = Arc::new(AbuseIpDbEnricher::new(key, cfg.abuseipdb.max_age_days)?);
                (
                    Arc::new(CachedEnricher::new(inner, Duration::from_secs(cfg.abuseipdb.cache_ttl_secs))),
                    "AbuseIPDB",
                )
            }
            (true, None) => {
                let _ = ui_tx.try_send(UiEvent::Notice(
                    "abuseipdb.enabled = true but no API key (set ABUSEIPDB_API_KEY); enrichment off".into(),
                ));
                (Arc::new(NoopEnricher), "off")
            }
            _ => (Arc::new(NoopEnricher), "off"),
        };

    let info = MonitorInfo {
        log_path: cfg.log_path.display().to_string(),
        discord_enabled: notifier.is_some(),
        enrichment,
    };

    // 1. tail
    {
        let tcfg = TailConfig {
            path: cfg.log_path.clone(),
            start_at_end: cfg.start_at_end,
            poll_interval: Duration::from_millis(cfg.poll_interval_ms.max(50)),
        };
        let (cancel, ui_tx) = (cancel.clone(), ui_tx.clone());
        tokio::spawn(async move {
            if let Err(e) = tail_file(tcfg, line_tx, cancel).await {
                let _ = ui_tx.send(UiEvent::Notice(format!("log reader stopped: {e:#}"))).await;
            }
        });
    }

    // 2. engine (parse + detect)
    tokio::spawn(engine_task(line_rx, alert_tx, ui_tx.clone(), stats.clone(), detector, cancel.clone()));

    // 3. dispatcher (throttle + enrich + notify)
    tokio::spawn(dispatch_task(
        alert_rx,
        ui_tx,
        stats.clone(),
        notifier,
        enricher,
        AlertThrottle::new(Duration::from_secs(cfg.discord.cooldown_secs), cfg.discord.max_per_minute),
    ));

    Ok(MonitorHandle { events: ui_rx, stats, info, cancel })
}

async fn engine_task(
    mut lines: mpsc::Receiver<String>,
    alerts: mpsc::Sender<Alert>,
    ui: mpsc::Sender<UiEvent>,
    stats: Arc<Stats>,
    mut detector: Detector,
    cancel: CancellationToken,
) {
    loop {
        let line = tokio::select! {
            _ = cancel.cancelled() => break,
            l = lines.recv() => match l { Some(l) => l, None => break },
        };
        stats.lines.fetch_add(1, Relaxed);
        let event = parser::parse_line(&line, Local::now());

        let _ = ui.try_send(UiEvent::Log(LogEntry {
            received: Utc::now(),
            tag: event.as_ref().map(|e| e.kind.label()),
            line,
        }));

        if let Some(ev) = event {
            stats.events.fetch_add(1, Relaxed);
            for alert in detector.process(&ev) {
                stats.alerts.fetch_add(1, Relaxed);
                if alerts.try_send(alert).is_err() {
                    stats.alerts_dropped.fetch_add(1, Relaxed);
                }
            }
            stats.tracked_ips.store(detector.tracked_ips(), Relaxed);
        }
    }
}

async fn dispatch_task(
    mut rx: mpsc::Receiver<Alert>,
    ui: mpsc::Sender<UiEvent>,
    stats: Arc<Stats>,
    notifier: Option<DiscordNotifier>,
    enricher: Arc<dyn IpEnricher>,
    mut throttle: AlertThrottle,
) {
    while let Some(mut alert) = rx.recv().await {
        let decision = throttle.check(&alert.dedupe_key, Instant::now());

        let delivery = match decision {
            Decision::Send { suppressed } => {
                // Only enrich alerts we will actually announce: saves API quota.
                if let Some(ip) = alert.src_ip {
                    let lookup = tokio::time::timeout(Duration::from_secs(10), enricher.lookup(ip)).await;
                    if let Ok(Ok(rep)) = lookup {
                        alert.reputation = rep;
                    }
                }
                match &notifier {
                    None => Delivery::Disabled,
                    Some(n) => match n.send(&alert, suppressed).await {
                        Ok(()) => {
                            stats.discord_sent.fetch_add(1, Relaxed);
                            Delivery::Sent
                        }
                        Err(e) => {
                            stats.discord_failed.fetch_add(1, Relaxed);
                            Delivery::Failed(format!("{e:#}"))
                        }
                    },
                }
            }
            Decision::Cooldown | Decision::GlobalLimit => {
                stats.discord_throttled.fetch_add(1, Relaxed);
                if notifier.is_some() { Delivery::Throttled } else { Delivery::Disabled }
            }
        };

        let _ = ui.try_send(UiEvent::Alert(AlertRecord { alert, delivery }));
    }
}
