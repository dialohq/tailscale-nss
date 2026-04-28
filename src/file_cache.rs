//! On-disk cache, written by the `tailscale-nss-syncd` daemon, read by the
//! NSS plugin.
//!
//! Decouples NSS lookup latency from network latency: with the daemon
//! running, every NSS call is one stat + one read of a few hundred bytes
//! instead of a tailscaled HTTP round-trip.
//!
//! Atomicity: the daemon writes to a tempfile and `rename(2)`s into place,
//! so readers always see either the previous version or the new version,
//! never a partial write.
//!
//! On-disk format: a JSON array of email strings. Only the email is
//! authoritative — `unix_name` and `uid` are pure functions of it and are
//! recomputed by [`TailnetUser::from_email`] on read. Storing them on disk
//! would invite a stale-derived-field class of bug.
//!
//! Stale-tolerance: a file older than [`MAX_AGE`] is treated as missing —
//! the daemon must have died, and we'd rather fall back to a live
//! tailscaled call than serve users from indefinitely-stale state.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::tailscale::TailnetUser;

/// Default location. `/run` is tmpfs on every reasonable Linux container
/// runtime, so reads are RAM-fast and writes don't hit disk.
pub const DEFAULT_CACHE_PATH: &str = "/run/tailscale-nss/users.json";

/// File-cache entries older than this are considered stale and ignored.
/// Two-minute window covers transient daemon restarts (s6 supervises so
/// it comes back fast) without serving from a permanently-dead daemon.
pub const MAX_AGE: Duration = Duration::from_secs(120);

pub fn cache_path() -> PathBuf {
    std::env::var_os("TAILSCALE_NSS_CACHE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_PATH))
}

/// Read users from the configured cache file. `Ok(None)` for "no usable
/// cache" — file missing, stale, or garbage — so callers can fall back to
/// a live tailscaled query rather than treating absence as an error.
pub fn read() -> io::Result<Option<Vec<TailnetUser>>> {
    read_from(&cache_path())
}

/// Atomically replace the configured cache file with `users`. Used by the
/// daemon; the NSS plugin never writes.
pub fn write(users: &[TailnetUser]) -> io::Result<()> {
    write_to(&cache_path(), users)
}

/// Path-explicit read. Public so tests can drive it without twiddling a
/// process-wide env var (the previous env-driven design raced under
/// `cargo test`'s parallel runner).
pub fn read_from(path: &Path) -> io::Result<Option<Vec<TailnetUser>>> {
    let raw = match fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    if let Some(age) = file_age(path) {
        if age > MAX_AGE {
            return Ok(None);
        }
    }

    let emails: Vec<String> = match serde_json::from_slice(&raw) {
        Ok(e) => e,
        // A partially-written file or schema skew shouldn't surface as
        // an error to NSS — fall through to a live fetch.
        Err(_) => return Ok(None),
    };
    Ok(Some(emails.into_iter().filter_map(TailnetUser::from_email).collect()))
}

/// Path-explicit write. Persists only the authoritative `email`; the
/// derived fields are reconstructed on read.
pub fn write_to(final_path: &Path, users: &[TailnetUser]) -> io::Result<()> {
    let parent = final_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cache path has no parent"))?;
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }

    // Suffix tempfile with pid so two concurrent daemon restarts (rare
    // but possible) don't trample each other. Both call `rename(2)`,
    // which is atomic — last writer wins, fine.
    let tmp_path = parent.join(format!(
        "{}.tmp.{}",
        final_path.file_name().and_then(|n| n.to_str()).unwrap_or("users.json"),
        std::process::id()
    ));

    let emails: Vec<&str> = users.iter().map(|u| u.email.as_str()).collect();
    let payload = serde_json::to_vec(&emails).map_err(io::Error::other)?;
    write_full(&tmp_path, &payload)?;
    fs::rename(&tmp_path, final_path)
}

fn file_age(path: &Path) -> Option<Duration> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now().duration_since(modified).ok()
}

fn write_full(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "ts-nss-cache-test-{tag}-{}-{nanos}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn roundtrip() {
        let p = fresh_path("roundtrip");
        let users = vec![
            TailnetUser::from_email("alice@dialo.ai".into()).unwrap(),
            TailnetUser::from_email("bob@dialo.ai".into()).unwrap(),
        ];
        write_to(&p, &users).expect("write");
        let read_back = read_from(&p).expect("read").expect("present");
        assert_eq!(read_back.len(), 2);
        assert_eq!(read_back[0].email, "alice@dialo.ai");
        // Derived fields recomputed on read, not loaded from disk:
        assert_eq!(read_back[0].unix_name, "alice");
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn missing_file_returns_none() {
        let p = fresh_path("missing");
        assert!(read_from(&p).expect("read").is_none());
    }

    #[test]
    fn garbage_file_returns_none() {
        let p = fresh_path("garbage");
        fs::write(&p, b"not json").unwrap();
        assert!(read_from(&p).expect("read").is_none());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn malformed_email_filtered_out() {
        let p = fresh_path("malformed");
        // "@dialo.ai" has an empty local-part — TailnetUser::from_email
        // rejects it; "alice@dialo.ai" is fine.
        fs::write(&p, br#"["alice@dialo.ai", "@dialo.ai"]"#).unwrap();
        let users = read_from(&p).expect("read").expect("present");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].email, "alice@dialo.ai");
        let _ = fs::remove_file(&p);
    }
}
