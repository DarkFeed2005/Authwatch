//! Cross-platform `tail -F` replacement (polling, no inotify dependency).
//!
//! Handles: partial lines, truncation, logrotate (inode change on Unix), and the
//! file not existing yet. Works the same on Linux, macOS and Windows.

use anyhow::Result;
use std::{fs::Metadata, path::PathBuf, time::Duration};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

const MAX_CHUNK: u64 = 1 << 20; // read at most 1 MiB per poll
const MAX_PARTIAL: usize = 64 * 1024; // flush absurdly long "lines"

#[derive(Debug, Clone)]
pub struct TailConfig {
    pub path: PathBuf,
    /// Skip existing content on the first open (live mode).
    pub start_at_end: bool,
    pub poll_interval: Duration,
}

#[cfg(unix)]
fn file_id(m: &Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((m.dev(), m.ino()))
}
#[cfg(not(unix))]
fn file_id(_: &Metadata) -> Option<(u64, u64)> {
    None
}

struct Open {
    file: File,
    pos: u64,
    id: Option<(u64, u64)>,
    partial: Vec<u8>,
}

pub async fn tail_file(cfg: TailConfig, tx: mpsc::Sender<String>, cancel: CancellationToken) -> Result<()> {
    let mut state: Option<Open> = None;
    let mut first_open = true;
    let mut warned_missing = false;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = tokio::time::sleep(cfg.poll_interval) => {}
        }

        let meta = match tokio::fs::metadata(&cfg.path).await {
            Ok(m) => m,
            Err(e) => {
                if !warned_missing {
                    tracing::warn!("cannot stat {}: {e} (will keep retrying)", cfg.path.display());
                    warned_missing = true;
                }
                state = None; // rotation in progress / file removed
                continue;
            }
        };
        warned_missing = false;
        let id = file_id(&meta);

        let reopen = match &state {
            None => true,
            Some(s) => s.id != id || meta.len() < s.pos, // rotated or truncated
        };
        if reopen {
            let file = match File::open(&cfg.path).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!("cannot open {}: {e}", cfg.path.display());
                    continue;
                }
            };
            let pos = if first_open && cfg.start_at_end { meta.len() } else { 0 };
            if !first_open {
                tracing::info!("{} was rotated or truncated; reopened", cfg.path.display());
            }
            first_open = false;
            state = Some(Open { file, pos, id, partial: Vec::new() });
        }

        let s = state.as_mut().expect("state set above");
        if meta.len() <= s.pos {
            continue;
        }

        let mut buf = Vec::new();
        s.file.seek(std::io::SeekFrom::Start(s.pos)).await?;
        let n = (&mut s.file).take(MAX_CHUNK).read_to_end(&mut buf).await?;
        s.pos += n as u64;
        s.partial.extend_from_slice(&buf);

        while let Some(nl) = s.partial.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = s.partial.drain(..=nl).collect();
            let line = String::from_utf8_lossy(&line_bytes).trim_end_matches(['\n', '\r']).to_string();
            if !line.is_empty() && tx.send(line).await.is_err() {
                return Ok(()); // receiver gone
            }
        }
        if s.partial.len() > MAX_PARTIAL {
            let line = String::from_utf8_lossy(&std::mem::take(&mut s.partial)).to_string();
            if tx.send(line).await.is_err() {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    async fn recv(rx: &mut mpsc::Receiver<String>) -> String {
        tokio::time::timeout(Duration::from_secs(3), rx.recv()).await.expect("timeout").expect("closed")
    }

    #[tokio::test]
    async fn follows_appends_partial_lines_and_truncation() {
        let path = std::env::temp_dir().join(format!("authwatch-tail-{}.log", std::process::id()));
        std::fs::write(&path, "old line\n").unwrap();

        let (tx, mut rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();
        let cfg = TailConfig { path: path.clone(), start_at_end: true, poll_interval: Duration::from_millis(20) };
        let h = tokio::spawn(tail_file(cfg, tx, cancel.clone()));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        write!(f, "first\nsec").unwrap();
        f.flush().unwrap();
        assert_eq!(recv(&mut rx).await, "first"); // "old line" skipped, partial held back
        write!(f, "ond\n").unwrap();
        f.flush().unwrap();
        assert_eq!(recv(&mut rx).await, "second");

        std::fs::write(&path, "after truncate\n").unwrap(); // truncation
        assert_eq!(recv(&mut rx).await, "after truncate");

        cancel.cancel();
        h.await.unwrap().unwrap();
        let _ = std::fs::remove_file(&path);
    }
}
