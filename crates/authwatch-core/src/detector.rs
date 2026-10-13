//! Stateful detection engine. Pure and synchronous: feed it [`AuthEvent`]s, get [`Alert`]s.
//!
//! All windows are evaluated against *event* timestamps (not wall-clock time), so
//! replaying an old log file produces the same alerts as watching it live.

use crate::alert::{Alert, AlertKind, Severity};
use crate::config::DetectionConfig;
use crate::event::{AuthEvent, EventKind};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;

struct Failure {
    ts: DateTime<Utc>,
    user: String,
}

struct IpState {
    failures: VecDeque<Failure>,
    last_seen: DateTime<Utc>,
}

pub struct Detector {
    cfg: DetectionConfig,
    sudo_rules: Vec<(String, Regex)>,
    ignore: HashSet<IpAddr>,
    ips: HashMap<IpAddr, IpState>,
    retention: Duration,
    latest: Option<DateTime<Utc>>,
    since_gc: usize,
}

impl Detector {
    pub fn new(cfg: DetectionConfig) -> Result<Self> {
        let sudo_rules = cfg
            .sudo_rules
            .iter()
            .map(|r| {
                Regex::new(&r.pattern)
                    .map(|re| (r.name.clone(), re))
                    .with_context(|| format!("invalid sudo rule '{}'", r.name))
            })
            .collect::<Result<Vec<_>>>()?;
        let retention = Duration::seconds(
            cfg.brute_force_window_secs
                .max(cfg.spray_window_secs)
                .max(cfg.compromise_window_secs),
        );
        Ok(Self {
            ignore: cfg.ignore_ips.iter().copied().collect(),
            cfg,
            sudo_rules,
            ips: HashMap::new(),
            retention,
            latest: None,
            since_gc: 0,
        })
    }

    pub fn tracked_ips(&self) -> usize {
        self.ips.len()
    }

    pub fn process(&mut self, ev: &AuthEvent) -> Vec<Alert> {
        self.latest = Some(self.latest.map_or(ev.timestamp, |l| l.max(ev.timestamp)));
        self.since_gc += 1;
        if self.since_gc >= 1000 || self.ips.len() >= self.cfg.max_tracked_ips {
            self.gc();
        }

        match &ev.kind {
            EventKind::FailedLogin { user, ip, .. } => self.on_failed(ev, user, *ip),
            EventKind::SuccessfulLogin { user, ip, method } => self.on_success(ev, user, *ip, method),
            EventKind::UserCreated { user, uid } => vec![mk(
                ev,
                AlertKind::NewUserAccount,
                Severity::High,
                None,
                Some(user.clone()),
                format!("A new local account '{user}' (UID {uid}) was created."),
                "Verify this was an authorised change. Attackers create accounts for persistence.".into(),
                format!("newuser:{user}"),
            )],
            EventKind::Sudo { invoker, target, command, tty, pwd } => {
                self.on_sudo(ev, invoker, target, command, tty.as_deref(), pwd)
            }
        }
    }

    fn on_failed(&mut self, ev: &AuthEvent, user: &str, ip: IpAddr) -> Vec<Alert> {
        if self.ignore.contains(&ip) {
            return vec![];
        }
        let (bf_n, bf_win) = (self.cfg.brute_force_threshold, self.cfg.brute_force_window_secs);
        let (sp_n, sp_win) = (self.cfg.spray_distinct_users, self.cfg.spray_window_secs);
        let cutoff = ev.timestamp - self.retention;

        let st = self.ips.entry(ip).or_insert_with(|| IpState {
            failures: VecDeque::new(),
            last_seen: ev.timestamp,
        });
        st.last_seen = ev.timestamp;
        st.failures.push_back(Failure { ts: ev.timestamp, user: user.to_string() });
        while st.failures.front().is_some_and(|f| f.ts < cutoff) {
            st.failures.pop_front();
        }

        let mut out = Vec::new();

        // Brute force: many failures from one IP in a short window.
        let bf_cut = ev.timestamp - Duration::seconds(bf_win);
        let bf: Vec<&Failure> = st.failures.iter().filter(|f| f.ts >= bf_cut).collect();
        if bf.len() >= bf_n {
            let distinct = bf.iter().map(|f| f.user.as_str()).collect::<HashSet<_>>().len();
            let severity = if bf.len() >= bf_n * 4 { Severity::High } else { Severity::Medium };
            out.push(mk(
                ev,
                AlertKind::BruteForce,
                severity,
                Some(ip),
                Some(user.to_string()),
                format!("{} failed logins from {ip} within {bf_win}s.", bf.len()),
                format!("Distinct usernames tried in window: {distinct}. Latest target: {user}."),
                format!("brute:{ip}"),
            ));
        }

        // Password spraying: many *different* usernames from one IP.
        let sp_cut = ev.timestamp - Duration::seconds(sp_win);
        let users: BTreeSet<&str> = st
            .failures
            .iter()
            .filter(|f| f.ts >= sp_cut)
            .map(|f| f.user.as_str())
            .collect();
        if users.len() >= sp_n {
            let shown: Vec<&str> = users.iter().copied().take(8).collect();
            let more = users.len().saturating_sub(shown.len());
            let mut list = shown.join(", ");
            if more > 0 {
                list.push_str(&format!(" (+{more} more)"));
            }
            out.push(mk(
                ev,
                AlertKind::PasswordSpray,
                Severity::High,
                Some(ip),
                Some(list.clone()),
                format!("{ip} attempted {} different usernames within {sp_win}s.", users.len()),
                format!("Usernames: {list}"),
                format!("spray:{ip}"),
            ));
        }
        out
    }

    fn on_success(&mut self, ev: &AuthEvent, user: &str, ip: IpAddr, method: &str) -> Vec<Alert> {
        if self.ignore.contains(&ip) {
            return vec![];
        }
        let cut = ev.timestamp - Duration::seconds(self.cfg.compromise_window_secs);
        let min = self.cfg.compromise_prior_failures;
        let Some(st) = self.ips.get_mut(&ip) else { return vec![] };

        let recent: Vec<&Failure> = st.failures.iter().filter(|f| f.ts >= cut).collect();
        if recent.len() < min {
            return vec![];
        }
        let total = recent.len();
        let same_user = recent.iter().filter(|f| f.user == user).count();
        let distinct = recent.iter().map(|f| f.user.as_str()).collect::<HashSet<_>>().len();
        let span = ev.timestamp - recent[0].ts;

        let alert = mk(
            ev,
            AlertKind::CompromisedAccount,
            Severity::Critical,
            Some(ip),
            Some(user.to_string()),
            format!("Successful {method} login for '{user}' from {ip} right after {total} failed attempts."),
            format!(
                "{same_user} of the failures targeted '{user}'; {distinct} distinct username(s) tried over {}s. \
                 Treat the account as compromised until proven otherwise.",
                span.num_seconds().max(0)
            ),
            format!("compromised:{ip}:{user}"),
        );
        st.failures.clear(); // consumed; don't re-fire on the next success
        vec![alert]
    }

    fn on_sudo(
        &self,
        ev: &AuthEvent,
        invoker: &str,
        target: &str,
        command: &str,
        tty: Option<&str>,
        pwd: &str,
    ) -> Vec<Alert> {
        let Some((rule, _)) = self.sudo_rules.iter().find(|(_, re)| re.is_match(command)) else {
            return vec![];
        };
        let severity = if target == "root" { Severity::High } else { Severity::Medium };
        vec![mk(
            ev,
            AlertKind::SuspiciousSudo,
            severity,
            None,
            Some(invoker.to_string()),
            format!("'{invoker}' ran a sudo command as '{target}' matching rule '{rule}'."),
            format!("Command: {command}\nTTY: {}\nPWD: {pwd}", tty.unwrap_or("-")),
            format!("sudo:{invoker}:{rule}"),
        )]
    }

    /// Drop stale per-IP state and enforce the memory cap.
    pub fn gc(&mut self) {
        self.since_gc = 0;
        let Some(latest) = self.latest else { return };
        let cutoff = latest - self.retention;
        self.ips.retain(|_, s| s.last_seen >= cutoff);

        let cap = self.cfg.max_tracked_ips;
        if self.ips.len() >= cap {
            // Still full: evict the least-recently-seen 10%.
            let mut by_age: Vec<(IpAddr, DateTime<Utc>)> =
                self.ips.iter().map(|(ip, s)| (*ip, s.last_seen)).collect();
            by_age.sort_by_key(|(_, t)| *t);
            for (ip, _) in by_age.into_iter().take((cap / 10).max(1)) {
                self.ips.remove(&ip);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn mk(
    ev: &AuthEvent,
    kind: AlertKind,
    severity: Severity,
    src_ip: Option<IpAddr>,
    username: Option<String>,
    summary: String,
    details: String,
    dedupe_key: String,
) -> Alert {
    Alert {
        timestamp: ev.timestamp,
        host: ev.host.clone(),
        kind,
        severity,
        src_ip,
        username,
        summary,
        details,
        evidence: Some(ev.raw.clone()),
        dedupe_key,
        reputation: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(sec: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 12, 10, 0, 0).unwrap() + Duration::seconds(sec)
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn ev(sec: i64, kind: EventKind) -> AuthEvent {
        AuthEvent { timestamp: t(sec), host: "h".into(), kind, raw: "raw".into() }
    }
    fn fail(sec: i64, user: &str, addr: &str) -> AuthEvent {
        ev(sec, EventKind::FailedLogin { user: user.into(), ip: ip(addr), invalid_user: false })
    }
    fn ok(sec: i64, user: &str, addr: &str) -> AuthEvent {
        ev(sec, EventKind::SuccessfulLogin { user: user.into(), ip: ip(addr), method: "password".into() })
    }
    fn det() -> Detector {
        Detector::new(DetectionConfig::default()).unwrap()
    }
    fn kinds(a: &[Alert]) -> Vec<AlertKind> {
        a.iter().map(|a| a.kind).collect()
    }

    #[test]
    fn brute_force_fires_at_threshold_only() {
        let mut d = det();
        for i in 0..4 {
            assert!(d.process(&fail(i, "root", "203.0.113.1")).is_empty());
        }
        let a = d.process(&fail(4, "root", "203.0.113.1"));
        assert_eq!(kinds(&a), vec![AlertKind::BruteForce]);
        assert_eq!(a[0].dedupe_key, "brute:203.0.113.1");
    }

    #[test]
    fn slow_failures_do_not_trigger() {
        let mut d = det();
        for i in 0..10 {
            assert!(d.process(&fail(i * 30, "root", "203.0.113.1")).is_empty());
        }
    }

    #[test]
    fn spraying_detected_across_usernames() {
        let mut d = det();
        let mut all = vec![];
        for (i, u) in ["a", "b", "c", "d"].iter().enumerate() {
            all.extend(d.process(&fail(i as i64 * 20, u, "198.51.100.7")));
        }
        assert!(kinds(&all).contains(&AlertKind::PasswordSpray));
        assert!(!kinds(&all).contains(&AlertKind::BruteForce)); // only 4 failures
    }

    #[test]
    fn success_after_failures_is_critical() {
        let mut d = det();
        for i in 0..3 {
            d.process(&fail(i, "bob", "192.0.2.5"));
        }
        let a = d.process(&ok(10, "bob", "192.0.2.5"));
        assert_eq!(kinds(&a), vec![AlertKind::CompromisedAccount]);
        assert_eq!(a[0].severity, Severity::Critical);
        // consumed: a second login does not re-alert
        assert!(d.process(&ok(20, "bob", "192.0.2.5")).is_empty());
    }

    #[test]
    fn clean_success_is_quiet() {
        let mut d = det();
        assert!(d.process(&ok(0, "bob", "192.0.2.5")).is_empty());
    }

    #[test]
    fn useradd_and_sudo() {
        let mut d = det();
        let a = d.process(&ev(0, EventKind::UserCreated { user: "evil".into(), uid: 1001 }));
        assert_eq!(kinds(&a), vec![AlertKind::NewUserAccount]);

        let sudo = |cmd: &str| {
            ev(1, EventKind::Sudo {
                invoker: "alice".into(), target: "root".into(), command: cmd.into(),
                tty: Some("pts/0".into()), pwd: "/".into(),
            })
        };
        assert_eq!(kinds(&d.process(&sudo("/usr/bin/cat /etc/shadow"))), vec![AlertKind::SuspiciousSudo]);
        assert_eq!(kinds(&d.process(&sudo("/bin/bash"))), vec![AlertKind::SuspiciousSudo]);
        assert!(d.process(&sudo("/usr/bin/apt update")).is_empty());
    }

    #[test]
    fn ignored_ips_are_skipped() {
        let mut cfg = DetectionConfig::default();
        cfg.ignore_ips = vec![ip("10.0.0.1")];
        let mut d = Detector::new(cfg).unwrap();
        for i in 0..20 {
            assert!(d.process(&fail(i, "root", "10.0.0.1")).is_empty());
        }
        assert_eq!(d.tracked_ips(), 0);
    }

    #[test]
    fn gc_expires_old_state() {
        let mut d = det();
        d.process(&fail(0, "root", "203.0.113.1"));
        d.process(&fail(5000, "root", "203.0.113.2"));
        d.gc();
        assert_eq!(d.tracked_ips(), 1);
    }
}
