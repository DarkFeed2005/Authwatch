//! Headless AuthWatch: prints alerts to stdout and (optionally) posts them to Discord.

use anyhow::Result;
use authwatch_core::{Config, Delivery, UiEvent};
use chrono::Local;
use clap::Parser;
use std::{path::PathBuf, sync::atomic::Ordering::Relaxed};

#[derive(Parser)]
#[command(version, about = "Real-time auth.log security monitor with Discord alerts")]
struct Args {
    /// Path to a TOML config file (see authwatch.example.toml)
    #[arg(short, long, env = "AUTHWATCH_CONFIG")]
    config: Option<PathBuf>,
    /// Log file to follow (overrides the config file)
    #[arg(short, long)]
    log_path: Option<PathBuf>,
    /// Replay the whole file first instead of starting at the end
    #[arg(long)]
    from_start: bool,
    /// Also print every parsed security event, not just alerts
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let mut cfg = Config::load(args.config.as_deref())?;
    if let Some(p) = args.log_path {
        cfg.log_path = p;
    }
    if args.from_start {
        cfg.start_at_end = false;
    }

    let mut monitor = authwatch_core::spawn(cfg)?;
    println!(
        "AuthWatch watching {} | discord: {} | enrichment: {}  (Ctrl-C to stop)",
        monitor.info.log_path,
        if monitor.info.discord_enabled { "on" } else { "off" },
        monitor.info.enrichment
    );

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            ev = monitor.events.recv() => match ev {
                None => break,
                Some(UiEvent::Notice(n)) => eprintln!("[notice] {n}"),
                Some(UiEvent::Log(l)) => {
                    if args.verbose && l.tag.is_some() {
                        println!("  event [{}] {}", l.tag.unwrap_or("-"), l.line);
                    }
                }
                Some(UiEvent::Alert(rec)) => {
                    let a = &rec.alert;
                    let t = a.kind.technique();
                    let delivery = match &rec.delivery {
                        Delivery::Sent => "sent".to_string(),
                        Delivery::Throttled => "throttled".to_string(),
                        Delivery::Disabled => "discord off".to_string(),
                        Delivery::Failed(e) => format!("FAILED: {e}"),
                    };
                    println!(
                        "[{}] {:<8} {} ({}) ip={} user={} | {}\n    {}",
                        a.timestamp.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S"),
                        a.severity.label(),
                        a.kind.label(),
                        t.id,
                        a.src_ip.map_or("-".into(), |i| i.to_string()),
                        a.username.as_deref().unwrap_or("-"),
                        delivery,
                        a.summary,
                    );
                }
            }
        }
    }

    let s = &monitor.stats;
    println!(
        "\nlines={} events={} alerts={} discord(sent={} throttled={} failed={})",
        s.lines.load(Relaxed), s.events.load(Relaxed), s.alerts.load(Relaxed),
        s.discord_sent.load(Relaxed), s.discord_throttled.load(Relaxed), s.discord_failed.load(Relaxed)
    );
    Ok(())
}
