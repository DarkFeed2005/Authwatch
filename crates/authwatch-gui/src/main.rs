//! AuthWatch desktop GUI (egui / eframe). Thin view layer over `authwatch-core`.

use anyhow::{anyhow, Result};
use authwatch_core::{
    monitor::{AlertRecord, Delivery, LogEntry, MonitorHandle, UiEvent},
    Alert, Config, Severity,
};
use chrono::{DateTime, Local, Utc};
use clap::Parser;
use eframe::egui::{self, Color32, RichText};
use std::{collections::VecDeque, path::PathBuf, sync::atomic::Ordering::Relaxed, time::Duration};

const MAX_LOG_LINES: usize = 5_000;
const MAX_ALERT_GROUPS: usize = 1_000;
const MAX_EVENTS_PER_FRAME: usize = 2_000;

#[derive(Parser)]
#[command(version, about = "AuthWatch desktop GUI")]
struct Args {
    /// Path to a TOML config file
    #[arg(short, long, env = "AUTHWATCH_CONFIG")]
    config: Option<PathBuf>,
    /// Log file to follow (overrides the config file)
    #[arg(short, long)]
    log_path: Option<PathBuf>,
    /// Replay the whole file first instead of starting at the end
    #[arg(long)]
    from_start: bool,
}

fn main() -> Result<()> {
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

    // The monitor pipeline lives on a Tokio runtime; egui owns the main thread.
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let _guard = rt.enter();
    let handle = authwatch_core::spawn(cfg)?;

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("AuthWatch")
            .with_inner_size([1150.0, 720.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };
    eframe::run_native("AuthWatch", options, Box::new(move |_cc| Ok(Box::new(App::new(handle)))))
        .map_err(|e| anyhow!("GUI error: {e}"))
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Alerts,
    Log,
}

/// Alerts with the same dedupe key collapse into one row with a counter.
struct AlertGroup {
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    count: u32,
    latest: Alert,
    delivery: Delivery,
}

struct App {
    handle: MonitorHandle,
    logs: VecDeque<LogEntry>,
    groups: Vec<AlertGroup>,
    notices: VecDeque<String>,
    tab: Tab,
    filter: String,
    only_events: bool,
    selected: Option<String>,
}

impl App {
    fn new(handle: MonitorHandle) -> Self {
        Self {
            handle,
            logs: VecDeque::new(),
            groups: Vec::new(),
            notices: VecDeque::new(),
            tab: Tab::Alerts,
            filter: String::new(),
            only_events: false,
            selected: None,
        }
    }

    fn drain_events(&mut self) {
        for _ in 0..MAX_EVENTS_PER_FRAME {
            let Ok(ev) = self.handle.events.try_recv() else { break };
            match ev {
                UiEvent::Log(l) => {
                    if self.logs.len() >= MAX_LOG_LINES {
                        self.logs.pop_front();
                    }
                    self.logs.push_back(l);
                }
                UiEvent::Alert(rec) => self.push_alert(rec),
                UiEvent::Notice(n) => {
                    if self.notices.len() >= 20 {
                        self.notices.pop_front();
                    }
                    self.notices.push_back(n);
                }
            }
        }
    }

    fn push_alert(&mut self, rec: AlertRecord) {
        let AlertRecord { alert, delivery } = rec;
        if let Some(g) = self.groups.iter_mut().find(|g| g.latest.dedupe_key == alert.dedupe_key) {
            g.count += 1;
            g.last_seen = alert.timestamp;
            // Keep the first successful delivery / reputation visible on the row.
            if delivery == Delivery::Sent || g.delivery == Delivery::Throttled && delivery != Delivery::Throttled {
                g.delivery = delivery;
            }
            let rep = alert.reputation.clone().or_else(|| g.latest.reputation.take());
            g.latest = alert;
            g.latest.reputation = rep;
        } else {
            self.groups.push(AlertGroup {
                first_seen: alert.timestamp,
                last_seen: alert.timestamp,
                count: 1,
                latest: alert,
                delivery,
            });
            if self.groups.len() > MAX_ALERT_GROUPS {
                self.groups.sort_by_key(|g| g.last_seen);
                self.groups.remove(0);
            }
        }
    }

    fn alerts_tab(&mut self, ui: &mut egui::Ui) {
        if self.groups.is_empty() {
            ui.add_space(24.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("No alerts yet — watching for suspicious activity…").weak());
            });
            return;
        }

        let mut order: Vec<usize> = (0..self.groups.len()).collect();
        order.sort_by(|a, b| self.groups[*b].last_seen.cmp(&self.groups[*a].last_seen));

        let mut clicked: Option<String> = None;
        egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
            egui::Grid::new("alerts").striped(true).num_columns(8).spacing([14.0, 6.0]).show(ui, |ui| {
                for h in ["Last seen", "Severity", "Type", "MITRE", "Source IP", "User", "Count", "Discord"] {
                    ui.label(RichText::new(h).strong());
                }
                ui.end_row();

                for i in order {
                    let g = &self.groups[i];
                    let a = &g.latest;
                    let is_sel = self.selected.as_deref() == Some(a.dedupe_key.as_str());
                    let when = g.last_seen.with_timezone(&Local).format("%H:%M:%S").to_string();

                    if ui.selectable_label(is_sel, when).clicked() {
                        clicked = Some(a.dedupe_key.clone());
                    }
                    ui.label(RichText::new(a.severity.label()).color(sev_color(a.severity)).strong());
                    ui.label(a.kind.label());
                    ui.label(RichText::new(a.kind.technique().id).monospace());
                    ui.label(RichText::new(a.src_ip.map_or("-".into(), |i| i.to_string())).monospace());
                    ui.label(truncate(a.username.as_deref().unwrap_or("-"), 28));
                    ui.label(g.count.to_string());
                    ui.label(delivery_text(&g.delivery));
                    ui.end_row();
                }
            });
        });
        if clicked.is_some() {
            self.selected = clicked;
        }
    }

    fn log_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("e.g. 203.0.113 or sshd").desired_width(260.0));
            ui.checkbox(&mut self.only_events, "Security events only");
            if ui.button("Clear").clicked() {
                self.logs.clear();
            }
        });
        ui.separator();

        let needle = self.filter.to_lowercase();
        let rows: Vec<&LogEntry> = self
            .logs
            .iter()
            .filter(|l| !self.only_events || l.tag.is_some())
            .filter(|l| needle.is_empty() || l.line.to_lowercase().contains(&needle))
            .collect();

        let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
        egui::ScrollArea::both().auto_shrink([false, false]).stick_to_bottom(true).show_rows(
            ui,
            row_h,
            rows.len(),
            |ui, range| {
                for l in &rows[range] {
                    let text = RichText::new(&l.line).monospace();
                    let text = match l.tag {
                        Some("FAILED") => text.color(Color32::from_rgb(235, 140, 60)),
                        Some("ACCEPTED") => text.color(Color32::from_rgb(90, 190, 120)),
                        Some(_) => text.color(Color32::from_rgb(230, 90, 90)),
                        None => text.weak(),
                    };
                    ui.add(egui::Label::new(text).extend().selectable(true));
                }
            },
        );
    }

    fn detail_panel(&self, ui: &mut egui::Ui) {
        let Some(key) = &self.selected else { return };
        let Some(g) = self.groups.iter().find(|g| &g.latest.dedupe_key == key) else { return };
        let a = &g.latest;
        let t = a.kind.technique();

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(a.kind.label()).heading().color(sev_color(a.severity)));
            ui.label(RichText::new(format!("{} · {} · {}", t.id, t.name, t.tactic)).weak());
        });
        ui.label(&a.summary);
        ui.label(format!(
            "First seen {} · last seen {} · {} occurrence(s) · host {} · Discord: {}",
            g.first_seen.with_timezone(&Local).format("%H:%M:%S"),
            g.last_seen.with_timezone(&Local).format("%H:%M:%S"),
            g.count,
            a.host,
            delivery_label(&g.delivery),
        ));
        if let Some(r) = &a.reputation {
            ui.label(format!(
                "{}: {}% confidence, {} reports {} {} {}",
                r.source,
                r.score,
                r.total_reports,
                r.country_code.as_deref().unwrap_or(""),
                r.isp.as_deref().unwrap_or(""),
                r.usage_type.as_deref().unwrap_or("")
            ));
        }
        ui.add_space(4.0);
        ui.label(RichText::new(&a.details).monospace());
        if let Some(ev) = &a.evidence {
            ui.add_space(4.0);
            ui.label(RichText::new("Evidence").strong());
            ui.add(egui::Label::new(RichText::new(ev).monospace().weak()).wrap().selectable(true));
        }
        if let Delivery::Failed(e) = &g.delivery {
            ui.colored_label(Color32::LIGHT_RED, format!("Discord error: {e}"));
        }
        ui.add_space(4.0);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();
        ctx.request_repaint_after(Duration::from_millis(200));

        let s = &self.handle.stats;
        let info = &self.handle.info;

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.heading("AuthWatch");
                ui.separator();
                ui.label(RichText::new("● monitoring").color(Color32::from_rgb(90, 190, 120)));
                ui.label(RichText::new(&info.log_path).monospace());
                ui.separator();
                status_pill(ui, "Discord", info.discord_enabled);
                status_pill(ui, "AbuseIPDB", info.enrichment != "off");
            });
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Alerts, format!("Alerts ({})", self.groups.len()));
                ui.selectable_value(&mut self.tab, Tab::Log, "Live log");
            });
            ui.add_space(2.0);
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "lines {} · events {} · alerts {} · tracked IPs {} · Discord sent {} / throttled {} / failed {}{}",
                    s.lines.load(Relaxed),
                    s.events.load(Relaxed),
                    s.alerts.load(Relaxed),
                    s.tracked_ips.load(Relaxed),
                    s.discord_sent.load(Relaxed),
                    s.discord_throttled.load(Relaxed),
                    s.discord_failed.load(Relaxed),
                    match s.alerts_dropped.load(Relaxed) {
                        0 => String::new(),
                        n => format!(" · dropped {n}"),
                    }
                ));
                if let Some(n) = self.notices.back() {
                    ui.separator();
                    ui.colored_label(Color32::LIGHT_YELLOW, n);
                }
            });
        });

        if self.tab == Tab::Alerts && self.selected.is_some() {
            egui::TopBottomPanel::bottom("detail").resizable(true).min_height(120.0).show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| self.detail_panel(ui));
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Alerts => self.alerts_tab(ui),
            Tab::Log => self.log_tab(ui),
        });
    }
}

fn status_pill(ui: &mut egui::Ui, name: &str, on: bool) {
    let (txt, col) = if on {
        (format!("{name}: on"), Color32::from_rgb(90, 190, 120))
    } else {
        (format!("{name}: off"), Color32::GRAY)
    };
    ui.label(RichText::new(txt).color(col));
}

fn sev_color(s: Severity) -> Color32 {
    match s {
        Severity::Low => Color32::from_rgb(90, 160, 230),
        Severity::Medium => Color32::from_rgb(235, 200, 70),
        Severity::High => Color32::from_rgb(240, 140, 50),
        Severity::Critical => Color32::from_rgb(235, 80, 80),
    }
}

fn delivery_label(d: &Delivery) -> &'static str {
    match d {
        Delivery::Sent => "sent",
        Delivery::Throttled => "throttled",
        Delivery::Disabled => "off",
        Delivery::Failed(_) => "failed",
    }
}

fn delivery_text(d: &Delivery) -> RichText {
    match d {
        Delivery::Sent => RichText::new("sent").color(Color32::from_rgb(90, 190, 120)),
        Delivery::Throttled => RichText::new("throttled").color(Color32::GRAY),
        Delivery::Disabled => RichText::new("off").weak(),
        Delivery::Failed(_) => RichText::new("failed").color(Color32::LIGHT_RED),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}
