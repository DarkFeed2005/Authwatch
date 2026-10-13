//! auth.log line parser.
//!
//! Supports both classic syslog timestamps (`Oct 12 10:15:01`) and the RFC 3339
//! timestamps used by newer rsyslog defaults (`2026-10-12T10:15:01.123456+05:30`).

use crate::event::{AuthEvent, EventKind};
use chrono::{DateTime, Datelike, Duration, Local, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use std::{net::IpAddr, sync::LazyLock};

static HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))|(?P<sys>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+(?P<host>\S+)\s+(?P<rest>.*)$",
    )
    .unwrap()
});

static FAILED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"sshd(?:\[\d+\])?:\s+Failed (?:password|publickey|keyboard-interactive/pam) for (?P<inv>invalid user )?(?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+)(?: port \d+)?",
    )
    .unwrap()
});

static ACCEPTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"sshd(?:\[\d+\])?:\s+Accepted (?P<method>[\w-]+) for (?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+)(?: port \d+)?",
    )
    .unwrap()
});

static USERADD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"useradd(?:\[\d+\])?:\s+new user: name=(?P<name>[^,\s]+), UID=(?P<uid>\d+)").unwrap()
});

static SUDO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"sudo(?:\[\d+\])?:\s+(?P<invoker>\S+)\s+:\s+(?:TTY=(?P<tty>\S+)\s+;\s+)?PWD=(?P<pwd>.+?)\s+;\s+USER=(?P<target>\S+)\s+;\s+COMMAND=(?P<cmd>.+)$",
    )
    .unwrap()
});

/// Parse one log line. Returns `None` for lines we don't care about.
pub fn parse_line(line: &str, now: DateTime<Local>) -> Option<AuthEvent> {
    let line = line.trim_end();
    let h = HEADER.captures(line)?;
    let timestamp = if let Some(iso) = h.name("iso") {
        DateTime::parse_from_rfc3339(iso.as_str()).ok()?.with_timezone(&Utc)
    } else {
        parse_syslog_ts(h.name("sys")?.as_str(), now).unwrap_or_else(|| now.with_timezone(&Utc))
    };
    let host = h["host"].to_string();
    let rest = &h["rest"];

    let kind = if let Some(c) = FAILED.captures(rest) {
        EventKind::FailedLogin {
            user: c["user"].to_string(),
            ip: c["ip"].parse::<IpAddr>().ok()?,
            invalid_user: c.name("inv").is_some(),
        }
    } else if let Some(c) = ACCEPTED.captures(rest) {
        EventKind::SuccessfulLogin {
            user: c["user"].to_string(),
            ip: c["ip"].parse::<IpAddr>().ok()?,
            method: c["method"].to_string(),
        }
    } else if let Some(c) = USERADD.captures(rest) {
        EventKind::UserCreated { user: c["name"].to_string(), uid: c["uid"].parse().ok()? }
    } else if let Some(c) = SUDO.captures(rest) {
        EventKind::Sudo {
            invoker: c["invoker"].to_string(),
            target: c["target"].to_string(),
            command: c["cmd"].trim().to_string(),
            tty: c.name("tty").map(|m| m.as_str().to_string()),
            pwd: c["pwd"].to_string(),
        }
    } else {
        return None;
    };

    Some(AuthEvent { timestamp, host, kind, raw: line.to_string() })
}

/// Syslog timestamps carry no year; assume the current one, and roll back a
/// year if that would put the event in the future (Dec lines read in January).
fn parse_syslog_ts(s: &str, now: DateTime<Local>) -> Option<DateTime<Utc>> {
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let try_year = |year: i32| -> Option<DateTime<Utc>> {
        let naive =
            NaiveDateTime::parse_from_str(&format!("{year} {collapsed}"), "%Y %b %d %H:%M:%S").ok()?;
        Some(Local.from_local_datetime(&naive).earliest()?.with_timezone(&Utc))
    };
    let ts = try_year(now.year())?;
    if ts > now.with_timezone(&Utc) + Duration::days(1) {
        try_year(now.year() - 1)
    } else {
        Some(ts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Local> {
        Local.with_ymd_and_hms(2026, 10, 12, 12, 0, 0).unwrap()
    }

    #[test]
    fn failed_password_invalid_user() {
        let l = "Oct 12 10:15:01 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.9 port 51022 ssh2";
        let e = parse_line(l, now()).unwrap();
        assert_eq!(e.host, "web01");
        match e.kind {
            EventKind::FailedLogin { user, ip, invalid_user } => {
                assert_eq!(user, "admin");
                assert_eq!(ip, "203.0.113.9".parse::<IpAddr>().unwrap());
                assert!(invalid_user);
            }
            k => panic!("unexpected {k:?}"),
        }
    }

    #[test]
    fn accepted_iso_timestamp_ipv6() {
        let l = "2026-10-12T10:15:01.123456+05:30 web01 sshd[99]: Accepted publickey for kalana from 2001:db8::1 port 40000 ssh2: ED25519 SHA256:abc";
        let e = parse_line(l, now()).unwrap();
        assert!(matches!(e.kind, EventKind::SuccessfulLogin { ref user, .. } if user == "kalana"));
        assert_eq!(e.timestamp.to_rfc3339(), "2026-10-12T04:45:01.123456+00:00");
    }

    #[test]
    fn useradd() {
        let l = "Oct  1 03:00:00 web01 useradd[555]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash";
        let e = parse_line(l, now()).unwrap();
        assert!(matches!(e.kind, EventKind::UserCreated { ref user, uid: 1002 } if user == "backdoor"));
    }

    #[test]
    fn sudo_with_args() {
        let l = "Oct 12 11:00:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow";
        let e = parse_line(l, now()).unwrap();
        match e.kind {
            EventKind::Sudo { invoker, target, command, tty, pwd } => {
                assert_eq!(invoker, "alice");
                assert_eq!(target, "root");
                assert_eq!(command, "/usr/bin/cat /etc/shadow");
                assert_eq!(tty.as_deref(), Some("pts/0"));
                assert_eq!(pwd, "/home/alice");
            }
            k => panic!("unexpected {k:?}"),
        }
    }

    #[test]
    fn year_rollover() {
        let jan = Local.with_ymd_and_hms(2026, 1, 2, 0, 5, 0).unwrap();
        let l = "Dec 31 23:59:59 h sshd[1]: Failed password for root from 198.51.100.1 port 22 ssh2";
        let e = parse_line(l, jan).unwrap();
        assert_eq!(e.timestamp.with_timezone(&Local).year(), 2025);
    }

    #[test]
    fn ignores_noise() {
        assert!(parse_line("Oct 12 10:15:01 h CRON[1]: pam_unix(cron:session): session opened", now()).is_none());
        assert!(parse_line("garbage", now()).is_none());
    }
}
