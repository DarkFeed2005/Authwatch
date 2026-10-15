//! Alert-fatigue control for outbound notifications.
//!
//! Two layers:
//! 1. **Per-key cooldown** – the same `dedupe_key` is sent at most once per cooldown.
//! 2. **Global cap** – at most `max_per_minute` messages overall (botnet protection).
//!
//! Suppressed alerts are counted and reported on the next message that does go out.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Send it; `suppressed` duplicates were swallowed since the last send for this key.
    Send { suppressed: u32 },
    Cooldown,
    GlobalLimit,
}

#[derive(Default)]
struct KeyState {
    last_sent: Option<Instant>,
    suppressed: u32,
}

pub struct AlertThrottle {
    cooldown: Duration,
    max_per_minute: usize,
    keys: HashMap<String, KeyState>,
    recent: VecDeque<Instant>,
}

impl AlertThrottle {
    pub fn new(cooldown: Duration, max_per_minute: usize) -> Self {
        Self { cooldown, max_per_minute: max_per_minute.max(1), keys: HashMap::new(), recent: VecDeque::new() }
    }

    pub fn check(&mut self, key: &str, now: Instant) -> Decision {
        self.evict(now);
        let state = self.keys.entry(key.to_string()).or_default();

        if let Some(last) = state.last_sent {
            if now.duration_since(last) < self.cooldown {
                state.suppressed = state.suppressed.saturating_add(1);
                return Decision::Cooldown;
            }
        }

        while self.recent.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60)) {
            self.recent.pop_front();
        }
        if self.recent.len() >= self.max_per_minute {
            state.suppressed = state.suppressed.saturating_add(1);
            return Decision::GlobalLimit;
        }

        let suppressed = std::mem::take(&mut state.suppressed);
        state.last_sent = Some(now);
        self.recent.push_back(now);
        Decision::Send { suppressed }
    }

    /// Keep the map bounded: forget keys that are past cooldown and have nothing pending.
    fn evict(&mut self, now: Instant) {
        if self.keys.len() < 4096 {
            return;
        }
        let cooldown = self.cooldown;
        self.keys.retain(|_, s| {
            s.suppressed > 0 || s.last_sent.is_some_and(|t| now.duration_since(t) < cooldown)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooldown_then_resume_with_count() {
        let mut t = AlertThrottle::new(Duration::from_secs(60), 100);
        let t0 = Instant::now();
        assert_eq!(t.check("k", t0), Decision::Send { suppressed: 0 });
        assert_eq!(t.check("k", t0 + Duration::from_secs(1)), Decision::Cooldown);
        assert_eq!(t.check("k", t0 + Duration::from_secs(30)), Decision::Cooldown);
        assert_eq!(t.check("other", t0 + Duration::from_secs(31)), Decision::Send { suppressed: 0 });
        assert_eq!(t.check("k", t0 + Duration::from_secs(61)), Decision::Send { suppressed: 2 });
    }

    #[test]
    fn global_cap() {
        let mut t = AlertThrottle::new(Duration::from_secs(60), 2);
        let t0 = Instant::now();
        assert!(matches!(t.check("a", t0), Decision::Send { .. }));
        assert!(matches!(t.check("b", t0), Decision::Send { .. }));
        assert_eq!(t.check("c", t0), Decision::GlobalLimit);
        // after the minute window frees up, "c" goes through and reports the miss
        assert_eq!(t.check("c", t0 + Duration::from_secs(61)), Decision::Send { suppressed: 1 });
    }
}
