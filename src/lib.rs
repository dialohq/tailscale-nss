//! NSS plugin that synthesizes UNIX users from a tailnet's peer list.
//!
//! Loaded into glibc's NSS via `/etc/nsswitch.conf` (e.g. `passwd: files tailscale`).
//! On every `getpwnam`/`getpwuid`/`getpwent` call, glibc invokes one of the
//! exported `_nss_tailscale_*` symbols, which delegate to the cached
//! [`tailscale::Snapshot`] and synthesize `Passwd`/`Group` rows.
//!
//! Hard rules for code in this crate:
//!   * Never panic. NSS plugins are loaded into every NSS-using process —
//!     sshd, ls, ps, sudo, …. A panic here crashes the host process.
//!     `panic = "abort"` in Cargo.toml means we *die* on a panic; better
//!     than unwinding through libc, but the goal is to not hit the path.
//!   * Bound every I/O call. A hung tailscaled socket would otherwise hang
//!     `id`, `getent`, every login attempt. See `tailscale::TIMEOUT`.
//!   * No allocations in `static` initializers. NSS is loaded by `dlopen`;
//!     surprising work at load time can break processes that just wanted
//!     to resolve a username.

use libnss::group::{Group, GroupHooks};
use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::{libnss_group_hooks, libnss_passwd_hooks};

pub mod config;
pub mod file_cache;
pub mod tailscale;
pub mod uid;

use tailscale::{Snapshot, TailnetUser};

struct TailscalePasswd;
libnss_passwd_hooks!(tailscale, TailscalePasswd);

impl PasswdHooks for TailscalePasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        all(synthesize_passwd)
    }
    fn get_entry_by_uid(uid: u32) -> Response<Passwd> {
        find(|s| s.find_by_uid(uid), synthesize_passwd)
    }
    fn get_entry_by_name(name: String) -> Response<Passwd> {
        find(|s| s.find_by_name(&name), synthesize_passwd)
    }
}

struct TailscaleGroup;
libnss_group_hooks!(tailscale, TailscaleGroup);

impl GroupHooks for TailscaleGroup {
    // One synthetic group per tailnet user (the conventional "primary
    // group per user" UNIX layout). Cheap because the tailnet is bounded.
    fn get_all_entries() -> Response<Vec<Group>> {
        all(synthesize_group)
    }
    fn get_entry_by_gid(gid: u32) -> Response<Group> {
        find(|s| s.find_by_uid(gid), synthesize_group)
    }
    fn get_entry_by_name(name: String) -> Response<Group> {
        find(|s| s.find_by_name(&name), synthesize_group)
    }
}

/// Single-user lookup. Failure to fetch the snapshot maps to `NotFound`
/// (NSS will fall through to the next configured source — typically
/// `files`, which still answers for `root`/system users).
fn find<T, F, S>(lookup: F, synth: S) -> Response<T>
where
    F: for<'a> FnOnce(&'a Snapshot) -> Option<&'a TailnetUser>,
    S: FnOnce(&TailnetUser) -> T,
{
    match tailscale::snapshot() {
        Ok(snap) => match lookup(&snap) {
            Some(u) => Response::Success(synth(u)),
            None => Response::NotFound,
        },
        Err(_) => Response::NotFound,
    }
}

/// Enumerate all users. Snapshot fetch failure returns an empty list
/// rather than `NotFound` because that's how NSS expresses "this source
/// has no entries to enumerate".
fn all<T>(synth: fn(&TailnetUser) -> T) -> Response<Vec<T>> {
    match tailscale::snapshot() {
        Ok(snap) => Response::Success(snap.iter().map(synth).collect()),
        Err(_) => Response::Success(Vec::new()),
    }
}

fn synthesize_passwd(u: &TailnetUser) -> Passwd {
    Passwd {
        name: u.unix_name.clone(),
        passwd: "x".to_string(),
        uid: u.uid,
        gid: u.uid,
        gecos: u.email.clone(),
        dir: format!("/home/{}", u.unix_name),
        shell: config::default_shell().to_string(),
    }
}

fn synthesize_group(u: &TailnetUser) -> Group {
    Group {
        name: u.unix_name.clone(),
        passwd: "x".to_string(),
        gid: u.uid,
        members: Vec::new(),
    }
}
