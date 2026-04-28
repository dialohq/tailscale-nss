//! Minimal client for tailscaled's local HTTP-over-Unix-socket API.
//!
//! We only need one endpoint: `GET /localapi/v0/status`. Pulling in `hyper` /
//! `reqwest` would inflate the `.so` and bring async runtimes into a
//! libc-loaded plugin; speaking HTTP/1.0 by hand is ~50 lines and has zero
//! surprises in `dlopen`-loaded contexts.
//!
//! Every entry point in this module enforces a hard timeout
//! ([`TIMEOUT`]). The whole point of the timeout is that *every* NSS-using
//! process on the box (sshd, ls, ps, sudo, the user's shell, …) blocks on
//! these calls. A hung tailscaled would otherwise wedge the entire system.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use serde::Deserialize;

use crate::config;

/// Hard upper bound on how long any single NSS lookup can wait on
/// tailscaled. NSS callers are interactive (shell prompts, `ls -l`) — anything
/// above ~100ms feels like a hang. 250ms gives slack for slow boxes; on
/// failure we return "no users from tailscale" and fall through to other
/// NSS sources (typically `files`).
const TIMEOUT: Duration = Duration::from_millis(250);

/// How long a successful tailscaled response is treated as fresh. Within this
/// window every NSS call is answered from process-local memory — no socket
/// hit, no JSON parse. Picked at 5s so that:
///   * `ls -l` on a directory with N tailnet-owned files makes one tailscaled
///     call total instead of N.
///   * "alice just joined the tailnet" still resolves within ~5s on the host,
///     well below human "why didn't it work" patience.
const CACHE_TTL: Duration = Duration::from_secs(5);

struct CacheEntry {
    fresh_until: Instant,
    users: Vec<TailnetUser>,
}

/// Process-local cache. NSS plugins run in every process that does name
/// lookups, but each process loads the `.so` independently, so this cache
/// gets created fresh per-process. That's fine — cache hit-rate is "as long
/// as one process is doing rapid lookups".
static CACHE: Lazy<Mutex<Option<CacheEntry>>> = Lazy::new(|| Mutex::new(None));

/// One synthesized UNIX user, derived from a tailnet peer.
#[derive(Debug, Clone)]
pub struct TailnetUser {
    /// Full identity, e.g. `"alice@dialo.ai"`.
    pub email: String,
}

impl TailnetUser {
    /// Local-part of the email, sanitized for use as a UNIX login name.
    pub fn unix_name(&self) -> String {
        self.email
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
}

#[derive(Debug)]
pub enum Error {
    Connect,
    Io,
    Parse,
}

/// Fetch the current peer list from tailscaled, filter to users in the
/// configured domain, and return them as `TailnetUser`s. Cached for
/// [`CACHE_TTL`].
///
/// Failure is communicated via `Err(_)` — callers in `lib.rs` translate that
/// into "no users from tailscale" (`Response::Success(vec![])` for
/// enumeration; `Response::NotFound` for lookups). Failing closed lets `files`
/// in `nsswitch.conf` still answer for `root` and other system users.
///
/// On a network failure we serve the *previous* successful result, even if
/// past its TTL. The thinking: a tailscaled hiccup shouldn't spuriously make
/// alice "disappear" from the system mid-session.
pub fn list_users() -> Result<Vec<TailnetUser>, Error> {
    // We deliberately recover from a poisoned mutex (`poisoned.into_inner()`):
    // poisoning here means a previous holder panicked, not that the data is
    // unsafe — and since this plugin gets `dlopen`'d into every NSS-using
    // process, surfacing a panic to the host process is far worse than reusing
    // possibly-half-updated state.
    let mut guard = match CACHE.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    let now = Instant::now();
    if let Some(entry) = guard.as_ref() {
        if now < entry.fresh_until {
            return Ok(entry.users.clone());
        }
    }

    match list_users_uncached() {
        Ok(users) => {
            *guard = Some(CacheEntry {
                fresh_until: now + CACHE_TTL,
                users: users.clone(),
            });
            Ok(users)
        }
        Err(err) => {
            // Graceful degradation: if we have *any* prior cached data, return
            // it rather than failing the lookup. Sshd authn already in flight
            // shouldn't break because tailscaled briefly stopped answering.
            if let Some(entry) = guard.as_ref() {
                return Ok(entry.users.clone());
            }
            Err(err)
        }
    }
}

fn list_users_uncached() -> Result<Vec<TailnetUser>, Error> {
    let raw = http_get_json(config::socket_path(), "/localapi/v0/status")?;
    let status: Status = serde_json::from_str(&raw).map_err(|_| Error::Parse)?;

    let allowed_suffix = config::allowed_domain().map(|d| format!("@{d}"));

    // Tailscale's `Status.User` is a map keyed by stringified UserID; each
    // value's `LoginName` is the canonical email. We filter to the configured
    // domain (or, if no domain is set, return nothing — failing closed).
    let Some(suffix) = allowed_suffix else {
        return Ok(Vec::new());
    };

    let mut out: Vec<TailnetUser> = status
        .user
        .into_values()
        .filter_map(|u| {
            let email = u.login_name?;
            if email.ends_with(&suffix) {
                Some(TailnetUser { email })
            } else {
                None
            }
        })
        .collect();

    // Stable iteration order makes `getent passwd` output deterministic.
    out.sort_by(|a, b| a.email.cmp(&b.email));
    out.dedup_by(|a, b| a.email == b.email);
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct Status {
    #[serde(rename = "User", default)]
    user: std::collections::HashMap<String, StatusUser>,
}

#[derive(Debug, Deserialize)]
struct StatusUser {
    #[serde(rename = "LoginName", default)]
    login_name: Option<String>,
}

/// Speak HTTP/1.0 to tailscaled over a unix socket; return the decoded body.
///
/// Hand-rolled to avoid pulling in `hyper`/`reqwest`. tailscaled's local API
/// answers HTTP/1.0 with `Content-Length` (no chunked, no keep-alive needed),
/// so this short path is exactly enough.
fn http_get_json(socket: &str, path: &str) -> Result<String, Error> {
    let mut stream = UnixStream::connect(socket).map_err(|_| Error::Connect)?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(|_| Error::Io)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(|_| Error::Io)?;

    // tailscaled requires a Host header but doesn't care about the value.
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: local-tailscaled.sock\r\nAccept: application/json\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).map_err(|_| Error::Io)?;

    let mut reader = BufReader::new(stream);

    // Status line.
    let mut status_line = String::new();
    reader.read_line(&mut status_line).map_err(|_| Error::Io)?;
    if !status_line.contains("200") {
        return Err(Error::Io);
    }

    // Headers — read until blank line, ignore.
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).map_err(|_| Error::Io)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    // Body — read until EOF (HTTP/1.0 + Connection: close).
    let mut body = String::new();
    reader.read_to_string(&mut body).map_err(|_| Error::Io)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_name_strips_domain() {
        let u = TailnetUser { email: "alice@dialo.ai".into() };
        assert_eq!(u.unix_name(), "alice");
    }

    #[test]
    fn unix_name_sanitizes() {
        let u = TailnetUser { email: "alice+work@dialo.ai".into() };
        assert_eq!(u.unix_name(), "alice_work");
    }
}

/// Failure-mode tests for [`http_get_json`].
///
/// These spin up a one-shot unix-socket "server" that emits canned bytes,
/// then verify the client behaves correctly on each variety of broken
/// response. The whole point is that an NSS plugin must never panic or hang
/// on bad upstream — every path here would otherwise crash or freeze sshd,
/// `ls`, login shells, etc. when tailscaled misbehaves.
#[cfg(test)]
mod failure_mode_tests {
    use super::*;
    use std::io::BufReader as StdBufReader;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Fresh socket path under `/tmp`, unique per test invocation. Removed
    /// on creation — `UnixListener::bind` requires the path to not exist.
    fn fresh_socket(tag: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("ts-nss-test-{tag}-{}-{nanos}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Bind a unix listener at `path` and accept one connection in a
    /// background thread, then run `handler(stream)` on it. Used to simulate
    /// every flavour of misbehaving server.
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
        // Give the bind a moment so the test client doesn't ECONNREFUSED.
        thread::sleep(Duration::from_millis(20));
    }

    /// Drain HTTP request headers from `stream` so the server can write a
    /// response without confusing the client.
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
    fn happy_path_parses_status() {
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
        let body = http_get_json(sock.to_str().unwrap(), "/localapi/v0/status")
            .expect("happy path");
        let parsed: Status = serde_json::from_str(&body).expect("parse");
        assert!(parsed.user.contains_key("123"));
    }

    #[test]
    fn http_500_returns_io_err() {
        let sock = fresh_socket("500");
        serve_once(&sock, |mut stream| {
            drain_request(&stream);
            let _ = stream.write_all(
                b"HTTP/1.0 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
            );
        });
        let r = http_get_json(sock.to_str().unwrap(), "/localapi/v0/status");
        // Status line check fails for non-200 → Error::Io.
        assert!(matches!(r, Err(Error::Io)));
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
        let parsed: Result<Status, _> = serde_json::from_str(&body);
        assert!(parsed.is_err());
    }

    #[test]
    fn slow_server_hits_read_timeout() {
        let sock = fresh_socket("slow");
        serve_once(&sock, |mut stream| {
            drain_request(&stream);
            // Send headers, then never the body. Read will block, then time out.
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 999\r\n\r\n");
            // Hold the stream open longer than TIMEOUT so the client's
            // read_to_string blocks until the read_timeout fires.
            std::thread::sleep(Duration::from_millis(500));
            // stream drops here, EOF. That's fine — the timeout already fired
            // and the test has moved on.
            let _ = stream.flush();
            // explicit shutdown to make sure no hang in test teardown
            let _ = stream.shutdown(std::net::Shutdown::Both);
            // Also explicitly read so the variable isn't unused.
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf);
        });
        let started = Instant::now();
        let r = http_get_json(sock.to_str().unwrap(), "/localapi/v0/status");
        let elapsed = started.elapsed();
        // Whatever happens, it must NOT have hung past TIMEOUT plus a small
        // grace (giving the kernel timeslice a chance).
        assert!(
            elapsed < TIMEOUT + Duration::from_millis(200),
            "lookup hung for {:?}, expected < {:?}",
            elapsed,
            TIMEOUT
        );
        assert!(r.is_err(), "expected Err on read timeout, got {:?}", r);
    }
}
