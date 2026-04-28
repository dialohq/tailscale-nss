//! Read-only configuration baked at process start.
//!
//! All knobs come from environment variables, intentionally:
//!   * NSS plugins are loaded into every process that does name lookups, so
//!     reading a config file at every call would be insane (and would have
//!     to handle every process's CWD/permissions).
//!   * Env vars are inherited from sshd / tailscaled / login shells, which is
//!     where the surrounding container/runtime sets policy.
//!
//! Knobs:
//!   * `TAILSCALE_NSS_DOMAIN` — only synthesize users whose tailnet identity
//!     ends with `@<this>`. Required; without it we'd happily expose every
//!     tailnet peer as a UNIX user, which is almost never what you want.
//!   * `TAILSCALE_NSS_SHELL` — login shell for synthesized users. Default
//!     `/bin/bash`.
//!   * `TAILSCALE_NSS_SOCKET` — path to tailscaled's local API socket.
//!     Default `/var/run/tailscale/tailscaled.sock`.
//!   * `TAILSCALE_NSS_UID_BASE` — minimum UID for synthesized users. Default
//!     `100000`. Must be high enough to not collide with the system passwd.

use once_cell::sync::Lazy;
use std::env;

pub const DEFAULT_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";
pub const DEFAULT_SHELL: &str = "/bin/bash";
pub const DEFAULT_UID_BASE: u32 = 100_000;

static DOMAIN: Lazy<Option<String>> = Lazy::new(|| env::var("TAILSCALE_NSS_DOMAIN").ok());
static SHELL: Lazy<String> =
    Lazy::new(|| env::var("TAILSCALE_NSS_SHELL").unwrap_or_else(|_| DEFAULT_SHELL.to_string()));
static SOCKET: Lazy<String> =
    Lazy::new(|| env::var("TAILSCALE_NSS_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string()));
static UID_BASE: Lazy<u32> = Lazy::new(|| {
    env::var("TAILSCALE_NSS_UID_BASE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_UID_BASE)
});

pub fn allowed_domain() -> Option<&'static str> {
    DOMAIN.as_deref()
}

pub fn default_shell() -> &'static str {
    &SHELL
}

pub fn socket_path() -> &'static str {
    &SOCKET
}

pub fn uid_base() -> u32 {
    *UID_BASE
}
