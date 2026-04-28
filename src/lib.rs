//! NSS plugin that synthesizes UNIX users from a tailnet's peer list.
//!
//! Loaded into glibc's NSS via `/etc/nsswitch.conf` (e.g. `passwd: files tailscale`).
//! On every `getpwnam`/`getpwuid`/`getpwent` call, glibc invokes one of the
//! exported `_nss_tailscale_*` symbols, which we synthesize from the local
//! tailscaled API socket.
//!
//! Hard rules for code in this crate:
//!   * Never panic. NSS plugins are loaded into every NSS-using process —
//!     sshd, ls, ps, sudo, …. A panic here crashes the host process.
//!     `panic = "abort"` in Cargo.toml means we *die* on a panic; better than
//!     unwinding through libc, but the goal is to not hit the path at all.
//!   * Bound every I/O call. A hung tailscaled socket would otherwise hang
//!     `id`, `getent`, every login attempt. See `tailscale::TIMEOUT`.
//!   * No allocations in `static` initializers. NSS is loaded by `dlopen`;
//!     surprising work at load time can break processes that just wanted to
//!     resolve a username.

use libnss::group::{Group, GroupHooks};
use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::{libnss_group_hooks, libnss_passwd_hooks};

mod config;
mod tailscale;
mod uid;

struct TailscalePasswd;
libnss_passwd_hooks!(tailscale, TailscalePasswd);

impl PasswdHooks for TailscalePasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        match tailscale::list_users() {
            Ok(users) => Response::Success(users.into_iter().map(synthesize_passwd).collect()),
            Err(_) => Response::Success(Vec::new()),
        }
    }

    fn get_entry_by_uid(uid: u32) -> Response<Passwd> {
        match tailscale::list_users() {
            Ok(users) => users
                .into_iter()
                .find(|u| uid::for_email(&u.email) == uid)
                .map(synthesize_passwd)
                .map(Response::Success)
                .unwrap_or(Response::NotFound),
            Err(_) => Response::NotFound,
        }
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        match tailscale::list_users() {
            Ok(users) => users
                .into_iter()
                .find(|u| u.unix_name() == name)
                .map(synthesize_passwd)
                .map(Response::Success)
                .unwrap_or(Response::NotFound),
            Err(_) => Response::NotFound,
        }
    }
}

struct TailscaleGroup;
libnss_group_hooks!(tailscale, TailscaleGroup);

impl GroupHooks for TailscaleGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        // One synthetic group per tailnet user (matching the conventional
        // "primary group per user" UNIX layout). Cheap because the tailnet
        // is bounded.
        match tailscale::list_users() {
            Ok(users) => Response::Success(users.into_iter().map(synthesize_group).collect()),
            Err(_) => Response::Success(Vec::new()),
        }
    }

    fn get_entry_by_gid(gid: u32) -> Response<Group> {
        match tailscale::list_users() {
            Ok(users) => users
                .into_iter()
                .find(|u| uid::for_email(&u.email) == gid)
                .map(synthesize_group)
                .map(Response::Success)
                .unwrap_or(Response::NotFound),
            Err(_) => Response::NotFound,
        }
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        match tailscale::list_users() {
            Ok(users) => users
                .into_iter()
                .find(|u| u.unix_name() == name)
                .map(synthesize_group)
                .map(Response::Success)
                .unwrap_or(Response::NotFound),
            Err(_) => Response::NotFound,
        }
    }
}

fn synthesize_passwd(u: tailscale::TailnetUser) -> Passwd {
    let id = uid::for_email(&u.email);
    let name = u.unix_name();
    Passwd {
        name: name.clone(),
        passwd: "x".to_string(),
        uid: id,
        gid: id,
        gecos: u.email,
        dir: format!("/home/{name}"),
        shell: config::default_shell(),
    }
}

fn synthesize_group(u: tailscale::TailnetUser) -> Group {
    let id = uid::for_email(&u.email);
    let name = u.unix_name();
    Group {
        name,
        passwd: "x".to_string(),
        gid: id,
        members: vec![],
    }
}
