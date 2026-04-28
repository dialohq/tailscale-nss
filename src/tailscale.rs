//! Tailscaled client + per-process snapshot cache.
//!
//! There is exactly one endpoint we hit: `GET /localapi/v0/status` over the
//! tailscaled UNIX socket. Pulling in `hyper` / `reqwest` would inflate the
//! `.so` and bring async runtimes into a libc-loaded plugin; speaking
//! HTTP/1.0 by hand is ~50 lines and has zero surprises in `dlopen`'d
//! contexts.
//!
//! Hard rules every entry point upholds:
//!
//!   * Bounded I/O. Every socket call carries [`TIMEOUT`]; a hung tailscaled
//!     would otherwise wedge `id`, `getent`, every login attempt, every
//!     `ls -l` on a tailnet-owned file.
//!   * No panics. NSS plugins are `dlopen`'d into every name-resolving
//!     process — sshd, ls, ps, sudo, … — so a panic crashes the host. We
//!     have `panic = "abort"` as a guardrail, but the goal is to never hit
//!     the path.
//!   * Single linear allocation per refresh. Lookups happen on the hot path
//!     of every `getpw*`/`getgr*`. We build [`Snapshot`] once with two hash
//!     indices and hand out `Arc<Snapshot>` clones — cache hits are a
//!     refcount bump.
//!
//! The flow:
//!
//!   1. NSS hook calls [`snapshot()`].
//!   2. We check the in-process [`CACHE`] (process-local — each NSS-using
//!      process loads the `.so` independently, so caches don't share).
//!   3. On miss we try the daemon-maintained file cache
//!      ([`file_cache::read`]); on success it's parsed once and indexed,
//!      then stored as `Arc<Snapshot>` for [`CACHE_TTL`].
//!   4. On miss-of-miss we hit tailscaled directly. Used early in container
//!      boot (before the daemon writes its first file) and on hosts running
//!      the plugin without the daemon.
//!
//! Failure is communicated via `Err(_)`; callers in `lib.rs` translate that
//! into "no users from tailscale" so `files` in `nsswitch.conf` still
//! answers for `root` and other system users.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use serde::Deserialize;

use crate::{config, file_cache, uid};

/// Hard upper bound on a single tailscaled call. NSS callers are interactive
/// (shell prompts, `ls -l`); >100ms feels like a hang. 250ms gives slack on
/// slow boxes; on failure we return "no users" and the next NSS module
/// answers.
const TIMEOUT: Duration = Duration::from_millis(250);

/// In-process cache freshness window. NSS lookups within this window answer
/// from RAM alone — refcount bump on `Arc<Snapshot>`, hash lookup, done.
/// Picked at 5s so:
///   * `ls -l` of a 100-file dir makes one tailscaled+file-cache fetch.
///   * "alice just joined the tailnet" is visible within ~5s.
const CACHE_TTL: Duration = Duration::from_secs(5);

/// One synthesized UNIX user, with all derived fields precomputed at
/// construction so the NSS hot path doesn't recompute per call.
///
/// `email` is the only authoritative field; `unix_name` and `uid` are pure
/// functions of it but we cache them so a 100-user tailnet doesn't hash
/// 100 emails on every `getpwuid` lookup.
#[derive(Debug, Clone)]
pub struct TailnetUser {
    /// Full identity, e.g. `"alice@dialo.ai"`. The only field that actually
    /// goes on disk; the others are reconstructed from this on read.
    pub email: String,
    /// Local-part of the email, sanitized to a UNIX-safe charset. Empty
    /// strings are rejected at construction (see [`TailnetUser::from_email`]).
    pub unix_name: String,
    /// Stable UID derived from FNV-1a of the email; see [`uid::for_email`].
    pub uid: u32,
}

impl TailnetUser {
    /// Construct a user from a raw tailnet email. Returns `None` for
    /// nonsensical inputs (no local part, all-non-alphanumeric local part)
    /// rather than producing a `Passwd` with an empty `name` and a
    /// `/home/` directory.
    pub fn from_email(email: String) -> Option<Self> {
        let unix_name = sanitize_local_part(&email);
        if unix_name.is_empty() {
            return None;
        }
        let uid = uid::for_email(&email);
        Some(Self { email, unix_name, uid })
    }
}

fn sanitize_local_part(email: &str) -> String {
    email
        .split('@')
        .next()
        .unwrap_or("")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Indexed view of the tailnet's UNIX-eligible peers. Stored once per
/// refresh, handed out as `Arc<Snapshot>` so cache hits cost a refcount
/// bump.
#[derive(Debug)]
pub struct Snapshot {
    users: Vec<TailnetUser>,
    by_name: HashMap<String, usize>,
    by_uid: HashMap<u32, usize>,
}

impl Snapshot {
    pub fn build(mut users: Vec<TailnetUser>) -> Self {
        // Stable iteration order. Avoids `getent passwd` flopping the row
        // order between calls and is required for the `dedup_by` below.
        users.sort_by(|a, b| a.email.cmp(&b.email));
        users.dedup_by(|a, b| a.email == b.email);

        // `with_capacity` on both maps so building the snapshot is one
        // allocation per index rather than `2 * (log2(N))` reallocations.
        let mut by_name = HashMap::with_capacity(users.len());
        let mut by_uid = HashMap::with_capacity(users.len());
        for (i, u) in users.iter().enumerate() {
            // First-write-wins on UID collisions: the FNV space is large
            // enough that this is practically impossible, but defensively
            // we don't want a colliding email to hijack alice's slot.
            by_name.entry(u.unix_name.clone()).or_insert(i);
            by_uid.entry(u.uid).or_insert(i);
        }
        Self { users, by_name, by_uid }
    }

    pub fn find_by_name(&self, name: &str) -> Option<&TailnetUser> {
        self.by_name.get(name).and_then(|&i| self.users.get(i))
    }

    pub fn find_by_uid(&self, uid: u32) -> Option<&TailnetUser> {
        self.by_uid.get(&uid).and_then(|&i| self.users.get(i))
    }

    pub fn iter(&self) -> std::slice::Iter<'_, TailnetUser> {
        self.users.iter()
    }

    pub fn emails(&self) -> impl Iterator<Item = &str> {
        self.users.iter().map(|u| u.email.as_str())
    }
}

struct CacheEntry {
    fresh_until: Instant,
    snapshot: Arc<Snapshot>,
}

/// Process-local cache. Each NSS-using process loads the `.so`
/// independently, so this is fresh per-process — that's fine; cache
/// hit-rate is "as long as one process is doing rapid lookups".
static CACHE: Lazy<Mutex<Option<CacheEntry>>> = Lazy::new(|| Mutex::new(None));

#[derive(Debug)]
pub enum Error {
    /// Connect to the tailscaled local API socket failed. Most often the
    /// socket doesn't exist (tailscaled isn't running) or permissions are
    /// wrong.
    Connect,
    /// Socket I/O failure: configuring timeouts, writing the request,
    /// reading the response, or the connection closed mid-stream.
    Io,
    /// Read timed out — tailscaled accepted the connection but didn't
    /// answer within [`TIMEOUT`].
    Timeout,
    /// tailscaled responded with a non-2xx HTTP status. The `u16` is the
    /// status code (or `0` if the line was malformed enough that we
    /// couldn't extract one).
    BadStatus(u16),
    /// JSON body didn't match the expected shape.
    Parse,
}

/// Get the current tailnet snapshot, going through the in-process cache,
/// then the daemon-written file cache, then a live tailscaled call. On
/// transient failure we serve the previous in-process snapshot if we have
/// one (an in-flight sshd authn shouldn't break because tailscaled
/// briefly stopped answering).
pub fn snapshot() -> Result<Arc<Snapshot>, Error> {
    let mut guard = match CACHE.lock() {
        Ok(g) => g,
        // Mutex poisoning here means a previous holder panicked. Recovering
        // is far better than letting the panic surface to the host process
        // via a re-panic — see crate-level safety comment.
        Err(poisoned) => poisoned.into_inner(),
    };

    let now = Instant::now();
    if let Some(entry) = guard.as_ref() {
        if now < entry.fresh_until {
            return Ok(entry.snapshot.clone());
        }
    }

    // Fast path: daemon-maintained file cache (tmpfs read, no network).
    if let Ok(Some(users)) = file_cache::read() {
        let snap = Arc::new(Snapshot::build(users));
        *guard = Some(CacheEntry { fresh_until: now + CACHE_TTL, snapshot: snap.clone() });
        return Ok(snap);
    }

    // Slow path: tailscaled directly.
    match fetch_uncached() {
        Ok(users) => {
            let snap = Arc::new(Snapshot::build(users));
            *guard = Some(CacheEntry { fresh_until: now + CACHE_TTL, snapshot: snap.clone() });
            Ok(snap)
        }
        Err(err) => {
            if let Some(entry) = guard.as_ref() {
                return Ok(entry.snapshot.clone());
            }
            Err(err)
        }
    }
}

/// Direct tailscaled fetch, bypassing all caches. Used by the daemon on
/// every poll cycle and by the plugin as a last resort.
pub fn fetch_uncached() -> Result<Vec<TailnetUser>, Error> {
    let raw = http_get_json(config::socket_path(), "/localapi/v0/status")?;
    let status: Status = serde_json::from_slice(&raw).map_err(|_| Error::Parse)?;

    let Some(domain) = config::allowed_domain() else {
        // Failing closed: without a domain pin we'd happily synthesize every
        // tailnet peer as a UNIX user. Almost never what anyone wants.
        return Ok(Vec::new());
    };
    let suffix = format!("@{domain}");

    Ok(status
        .user
        .into_values()
        .filter_map(|u| u.login_name)
        .filter(|email| email.ends_with(&suffix))
        .filter_map(TailnetUser::from_email)
        .collect())
}

#[derive(Debug, Deserialize)]
struct Status {
    #[serde(rename = "User", default)]
    user: HashMap<String, StatusUser>,
}

#[derive(Debug, Deserialize)]
struct StatusUser {
    #[serde(rename = "LoginName", default)]
    login_name: Option<String>,
}

/// Speak HTTP/1.0 to tailscaled over a unix socket; return the body bytes.
/// Hand-rolled to avoid pulling `hyper`/`reqwest` into a `dlopen`'d plugin.
fn http_get_json(socket: &str, path: &str) -> Result<Vec<u8>, Error> {
    let mut stream = UnixStream::connect(socket).map_err(|_| Error::Connect)?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(|_| Error::Io)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(|_| Error::Io)?;

    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: local-tailscaled.sock\r\nAccept: application/json\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).map_err(map_io_err)?;

    let mut reader = BufReader::new(stream);

    // Status line: `HTTP/1.x <code> <reason>`. Anything that doesn't match
    // is treated as `BadStatus(0)` — we want better diagnostics than
    // "Io" for the case where tailscaled answered with garbage.
    let mut status_line = String::new();
    reader.read_line(&mut status_line).map_err(map_io_err)?;
    let code = parse_http_status(&status_line).ok_or(Error::BadStatus(0))?;
    if !(200..300).contains(&code) {
        return Err(Error::BadStatus(code));
    }

    // Drain headers until blank line. We don't need them.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).map_err(map_io_err)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    // Body — read until EOF (HTTP/1.0 + Connection: close).
    let mut body = Vec::new();
    reader.read_to_end(&mut body).map_err(map_io_err)?;
    Ok(body)
}

fn map_io_err(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Error::Timeout,
        _ => Error::Io,
    }
}

/// Extract the integer status code from an HTTP status line like
/// `"HTTP/1.0 200 OK\r\n"`. Returns `None` if the line doesn't have the
/// `HTTP/` prefix or the code isn't a 3-digit integer.
fn parse_http_status(line: &str) -> Option<u16> {
    let rest = line.strip_prefix("HTTP/")?;
    // Skip the version (e.g. "1.0", "1.1") up to the first space.
    let after_version = rest.split_once(' ')?.1;
    let code_str = after_version.split_whitespace().next()?;
    code_str.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_email_strips_domain() {
        let u = TailnetUser::from_email("alice@dialo.ai".into()).expect("valid");
        assert_eq!(u.unix_name, "alice");
    }

    #[test]
    fn from_email_sanitizes_local_part() {
        let u = TailnetUser::from_email("alice+work@dialo.ai".into()).expect("valid");
        assert_eq!(u.unix_name, "alice_work");
    }

    #[test]
    fn from_email_rejects_empty_local_part() {
        assert!(TailnetUser::from_email("@dialo.ai".into()).is_none());
        assert!(TailnetUser::from_email("".into()).is_none());
    }

    #[test]
    fn snapshot_indexes_lookups() {
        let users = vec![
            TailnetUser::from_email("alice@dialo.ai".into()).unwrap(),
            TailnetUser::from_email("bob@dialo.ai".into()).unwrap(),
        ];
        let snap = Snapshot::build(users);
        assert_eq!(snap.find_by_name("alice").map(|u| u.email.as_str()), Some("alice@dialo.ai"));
        assert!(snap.find_by_name("charlie").is_none());

        let alice_uid = uid::for_email("alice@dialo.ai");
        assert_eq!(snap.find_by_uid(alice_uid).map(|u| u.email.as_str()), Some("alice@dialo.ai"));
        assert!(snap.find_by_uid(0).is_none());
    }

    #[test]
    fn snapshot_dedups_and_sorts() {
        let users = vec![
            TailnetUser::from_email("bob@dialo.ai".into()).unwrap(),
            TailnetUser::from_email("alice@dialo.ai".into()).unwrap(),
            TailnetUser::from_email("alice@dialo.ai".into()).unwrap(),
        ];
        let snap = Snapshot::build(users);
        let emails: Vec<_> = snap.emails().collect();
        assert_eq!(emails, vec!["alice@dialo.ai", "bob@dialo.ai"]);
    }

    #[test]
    fn parse_http_status_extracts_code() {
        assert_eq!(parse_http_status("HTTP/1.0 200 OK\r\n"), Some(200));
        assert_eq!(parse_http_status("HTTP/1.1 404 Not Found\r\n"), Some(404));
        assert_eq!(parse_http_status("HTTP/1.0 500\r\n"), Some(500));
        // Failure modes:
        assert_eq!(parse_http_status("not http\r\n"), None);
        assert_eq!(parse_http_status("HTTP/1.0\r\n"), None);
        assert_eq!(parse_http_status("HTTP/1.0 nope OK\r\n"), None);
    }
}

/// Failure-mode tests for [`http_get_json`]. NSS plugins must never panic
/// or hang — these spin up a one-shot unix-socket "server" that emits
/// canned bytes and verify the client behaves correctly on each variety
/// of broken response.
#[cfg(test)]
mod failure_mode_tests {
    use super::*;
    use std::io::BufReader as StdBufReader;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fresh_socket(tag: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir()
            .join(format!("ts-nss-test-{tag}-{}-{nanos}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn serve_once(
        path: &std::path::Path,
        handler: impl FnOnce(std::os::unix::net::UnixStream) + Send + 'static,
    ) {
        let listener = UnixListener::bind(path).expect("bind test socket");
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handler(stream);
            }
        });
        thread::sleep(Duration::from_millis(20));
    }

    fn drain_request(stream: &std::os::unix::net::UnixStream) {
        let mut reader = StdBufReader::new(stream);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) if line == "\r\n" || line == "\n" => break,
                _ => {}
            }
        }
    }

    #[test]
    fn happy_path_returns_body_bytes() {
        let sock = fresh_socket("happy");
        serve_once(&sock, |mut stream| {
            drain_request(&stream);
            let body = r#"{"User":{"123":{"LoginName":"alice@dialo.ai"}}}"#;
            let response = format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let body = http_get_json(sock.to_str().unwrap(), "/localapi/v0/status").expect("ok");
        let parsed: Status = serde_json::from_slice(&body).expect("parse");
        assert_eq!(
            parsed.user.get("123").and_then(|u| u.login_name.as_deref()),
            Some("alice@dialo.ai")
        );
    }

    #[test]
    fn http_500_returns_bad_status() {
        let sock = fresh_socket("500");
        serve_once(&sock, |mut stream| {
            drain_request(&stream);
            let _ = stream.write_all(b"HTTP/1.0 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
        });
        let r = http_get_json(sock.to_str().unwrap(), "/localapi/v0/status");
        assert!(matches!(r, Err(Error::BadStatus(500))), "got {r:?}");
    }

    #[test]
    fn missing_socket_returns_connect_err() {
        let r = http_get_json(
            "/this/path/should/never/exist/tailscaled.sock",
            "/localapi/v0/status",
        );
        assert!(matches!(r, Err(Error::Connect)));
    }

    #[test]
    fn malformed_json_caught_at_parse() {
        let sock = fresh_socket("garbage");
        serve_once(&sock, |mut stream| {
            drain_request(&stream);
            let body = "not json at all";
            let response = format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let body = http_get_json(sock.to_str().unwrap(), "/localapi/v0/status").unwrap();
        let parsed: Result<Status, _> = serde_json::from_slice(&body);
        assert!(parsed.is_err());
    }

    #[test]
    fn slow_server_hits_read_timeout() {
        let sock = fresh_socket("slow");
        serve_once(&sock, |mut stream| {
            drain_request(&stream);
            // Send headers, then sit on the body well past TIMEOUT so the
            // read timeout fires unambiguously. 5s is way more than the
            // 250ms TIMEOUT plus any CI scheduling jitter.
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 999\r\n\r\n");
            std::thread::sleep(Duration::from_secs(5));
        });
        let started = Instant::now();
        let r = http_get_json(sock.to_str().unwrap(), "/localapi/v0/status");
        let elapsed = started.elapsed();
        // Must not hang past TIMEOUT + a generous grace.
        assert!(
            elapsed < TIMEOUT + Duration::from_millis(500),
            "lookup hung for {:?}, expected < {:?}",
            elapsed,
            TIMEOUT
        );
        assert!(matches!(r, Err(Error::Timeout) | Err(Error::Io)), "got {r:?}");
    }
}
