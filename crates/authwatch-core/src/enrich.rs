//! IP enrichment hook. Implement [`IpEnricher`] to plug in any reputation source.
//!
//! Shipped implementations:
//! * [`NoopEnricher`]      – default, does nothing.
//! * [`AbuseIpDbEnricher`] – AbuseIPDB v2 `/check` endpoint.
//! * [`CachedEnricher`]    – TTL cache wrapper (protects your API quota).

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpReputation {
    pub source: &'static str,
    /// 0–100 abuse confidence score.
    pub score: u8,
    pub total_reports: u32,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub usage_type: Option<String>,
}

#[async_trait]
pub trait IpEnricher: Send + Sync {
    /// `Ok(None)` = nothing known / not applicable. `Err` = transient failure.
    async fn lookup(&self, ip: IpAddr) -> Result<Option<IpReputation>>;
}

pub struct NoopEnricher;

#[async_trait]
impl IpEnricher for NoopEnricher {
    async fn lookup(&self, _ip: IpAddr) -> Result<Option<IpReputation>> {
        Ok(None)
    }
}

/// Private, loopback and link-local addresses are never worth a lookup.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
                || v4.is_broadcast() || v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            !(v6.is_loopback() || v6.is_unspecified() || (s0 & 0xfe00) == 0xfc00 || (s0 & 0xffc0) == 0xfe80)
        }
    }
}

// ---------------------------------------------------------------- AbuseIPDB

pub struct AbuseIpDbEnricher {
    client: reqwest::Client,
    api_key: String,
    max_age_days: u32,
}

#[derive(Deserialize)]
struct AbuseResponse {
    data: AbuseData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbuseData {
    abuse_confidence_score: u8,
    #[serde(default)]
    total_reports: u32,
    country_code: Option<String>,
    isp: Option<String>,
    usage_type: Option<String>,
}

impl AbuseIpDbEnricher {
    pub fn new(api_key: String, max_age_days: u32) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .user_agent(concat!("authwatch/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { client, api_key, max_age_days })
    }
}

#[async_trait]
impl IpEnricher for AbuseIpDbEnricher {
    async fn lookup(&self, ip: IpAddr) -> Result<Option<IpReputation>> {
        if !is_public_ip(ip) {
            return Ok(None);
        }
        let resp = self
            .client
            .get("https://api.abuseipdb.com/api/v2/check")
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .query(&[("ipAddress", ip.to_string()), ("maxAgeInDays", self.max_age_days.to_string())])
            .send()
            .await
            .context("AbuseIPDB request failed")?
            .error_for_status()
            .context("AbuseIPDB returned an error status")?;
        let body: AbuseResponse = resp.json().await.context("AbuseIPDB response parse")?;
        let d = body.data;
        Ok(Some(IpReputation {
            source: "AbuseIPDB",
            score: d.abuse_confidence_score,
            total_reports: d.total_reports,
            country_code: d.country_code,
            isp: d.isp,
            usage_type: d.usage_type,
        }))
    }
}

// -------------------------------------------------------------------- cache

pub struct CachedEnricher {
    inner: Arc<dyn IpEnricher>,
    ttl: Duration,
    error_ttl: Duration,
    cache: Mutex<HashMap<IpAddr, (Instant, Option<IpReputation>)>>,
}

impl CachedEnricher {
    pub fn new(inner: Arc<dyn IpEnricher>, ttl: Duration) -> Self {
        Self { inner, ttl, error_ttl: Duration::from_secs(300), cache: Mutex::new(HashMap::new()) }
    }
}

#[async_trait]
impl IpEnricher for CachedEnricher {
    async fn lookup(&self, ip: IpAddr) -> Result<Option<IpReputation>> {
        if let Some((expires, v)) = self.cache.lock().unwrap().get(&ip) {
            if *expires > Instant::now() {
                return Ok(v.clone());
            }
        }
        let (value, ttl) = match self.inner.lookup(ip).await {
            Ok(v) => (v, self.ttl),
            Err(e) => {
                tracing::warn!("enrichment lookup for {ip} failed: {e:#}");
                (None, self.error_ttl) // negative-cache failures briefly
            }
        };
        let mut cache = self.cache.lock().unwrap();
        if cache.len() > 50_000 {
            let now = Instant::now();
            cache.retain(|_, (exp, _)| *exp > now);
        }
        cache.insert(ip, (Instant::now() + ttl, value.clone()));
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting(AtomicUsize);
    #[async_trait]
    impl IpEnricher for Counting {
        async fn lookup(&self, _ip: IpAddr) -> Result<Option<IpReputation>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }
    }

    #[test]
    fn public_ip_filter() {
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_public_ip("192.168.1.5".parse().unwrap()));
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("fd00::1".parse().unwrap()));
        assert!(is_public_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[tokio::test]
    async fn cache_avoids_repeat_lookups() {
        let inner = Arc::new(Counting(AtomicUsize::new(0)));
        let c = CachedEnricher::new(inner.clone(), Duration::from_secs(60));
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        c.lookup(ip).await.unwrap();
        c.lookup(ip).await.unwrap();
        assert_eq!(inner.0.load(Ordering::SeqCst), 1);
    }
}
