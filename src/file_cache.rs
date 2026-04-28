//! On-disk cache, written by the `tailscale-nss-syncd` daemon, read by the
//! NSS plugin.
//!
//! The point of this layer is decoupling NSS lookup latency from network
//! latency. Without it, the first NSS call after the in-process cache TTL
//! pays the full tailscaled HTTP round-trip — which is fine on a healthy box
//! but turns `ls -l` into a stutter on a flaky network. With it, every NSS
//! call is one stat + one read of a few hundred bytes.
//!
//! The daemon writes via `tempfile + rename(2)`, which on Linux is atomic
//! within a filesystem. Readers always see either the previous version or
//! the new version, never a partial write. tmpfs on `/run` is the standard
//! home for runtime state of this kind — it gets blown away on container
//! restart, which is exactly what we want (the daemon repopulates within 5s
//! of starting).
//!
//! Stale-tolerance: a file older than [`MAX_AGE`] is treated as missing —
//! the daemon must have died, and we'd rather fall back to a live tailscaled
//! call than serve users from stale state indefinitely.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::tailscale::TailnetUser;

/// Default location. `/run` is tmpfs on every reasonable Linux container
/// runtime, so reads are RAM-fast and writes don't hit disk.
pub const DEFAULT_CACHE_PATH: &str = "/run/tailscale-nss/users.json";

/// File-cache entries older than this are considered stale and ignored.
/// Two-minute window covers transient daemon restarts (s6 supervises so it
/// comes back fast) without indefinitely serving from a permanently-dead
/// daemon. The in-process cache TTL is 5s, so this only kicks in when the
/// in-process cache also expires.
pub const MAX_AGE: Duration = Duration::from_secs(120);

/// Path is overridable via `TAILSCALE_NSS_CACHE_FILE` in case the daemon and
/// plugin need to agree on something other than `/run/tailscale-nss/users.json`
/// (tests, embedded scenarios).
pub fn cache_path() -> PathBuf {
    std::env::var_os("TAILSCALE_NSS_CACHE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_PATH))
}

/// Read users from the configured cache file. Returns `Ok(None)` when
/// there is no usable cache (file missing, too old, or unparseable) so
/// callers can fall back to a live tailscaled query rather than treating
/// absence as an error.
pub fn read() -> io::Result<Option<Vec<TailnetUser>>> {
    read_from(&cache_path())
}

/// Atomically replace the configured cache file with a serialization of
/// `users`. Used by the daemon; the NSS plugin never writes.
pub fn write(users: &[TailnetUser]) -> io::Result<()> {
    write_to(&cache_path(), users)
}

/// Path-explicit read. Public for tests so we don't have to twiddle a
/// process-wide env var (the previous design raced under `cargo test`'s
/// parallel runner).
pub fn read_from(path: &Path) -> io::Result<Option<Vec<TailnetUser>>> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    if let Ok(modified) = meta.modified() {
        if let Ok(age) = SystemTime::now().duration_since(modified) {
            if age > MAX_AGE {
                return Ok(None);
            }
        }
    }

    let raw = fs::read(path)?;
    match serde_json::from_slice::<Vec<TailnetUser>>(&raw) {
        Ok(users) => Ok(Some(users)),
        // Garbage from a partially-written file or schema skew shouldn't
        // surface as an error to NSS — fall through to a live fetch.
        Err(_) => Ok(None),
    }
}

/// Path-explicit write.
pub fn write_to(final_path: &Path, users: &[TailnetUser]) -> io::Result<()> {
    let parent = final_path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cache path has no parent"))?;
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }

    // Suffix the temp name with our pid so concurrent daemon restarts
    // (rare but possible) can't trample each other's tempfile. They'd both
    // call `rename(2)`, which on Linux is atomic — last writer wins, fine.
    let tmp_path = parent.join(format!(
        "{}.tmp.{}",
        final_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("users.json"),
        std::process::id()
    ));

    let payload = serde_json::to_vec(users).map_err(io::Error::other)?;
    write_full(&tmp_path, &payload)?;
    fs::rename(&tmp_path, final_path)
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
            TailnetUser { email: "alice@dialo.ai".into() },
            TailnetUser { email: "bob@dialo.ai".into() },
        ];
        write_to(&p, &users).expect("write");
        let read_back = read_from(&p).expect("read").expect("present");
        assert_eq!(read_back.len(), 2);
        assert_eq!(read_back[0].email, "alice@dialo.ai");
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn missing_file_returns_none() {
        let p = fresh_path("missing");
        let r = read_from(&p).expect("read");
        assert!(r.is_none(), "expected None for missing file");
    }

    #[test]
    fn garbage_file_returns_none() {
        let p = fresh_path("garbage");
        fs::write(&p, b"not json").unwrap();
        let r = read_from(&p).expect("read");
        assert!(r.is_none(), "expected None for unparseable file");
        let _ = fs::remove_file(&p);
    }
}
