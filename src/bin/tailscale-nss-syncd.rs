//! Side-car daemon for the `tailscale-nss` plugin.
//!
//! Runs as root. On every tick (`SYNC_INTERVAL`) it:
//!
//!   1. Asks tailscaled for the current peer list
//!   2. Atomically writes the result to `/run/tailscale-nss/users.json`,
//!      so NSS lookups in any process answer from a tmpfs file read instead
//!      of a tailscaled HTTP round-trip
//!   3. For each synthesized user, ensures `/home/<name>` exists with the
//!      right ownership — Tailscale SSH won't create the home dir, and
//!      `pam_mkhomedir` doesn't fire when sshd is configured `UsePAM no`,
//!      so we do it here. Idempotent: a `stat` on a present dir is a few
//!      microseconds.
//!
//! Failure handling:
//!
//!   * Failed tailscaled call: log to stderr, leave the file cache as-is
//!     (NSS plugin's 2-minute staleness ceiling will eventually kick in
//!     and force a live fallback).
//!   * Failed file write: log, retry next tick.
//!   * Failed home-dir creation: log per-user, continue with the rest.
//!
//! No process should ever exit on transient errors — s6 would restart us
//! anyway, but the no-restart path is faster and avoids log spam.

use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

use nss_tailscale::file_cache;
use nss_tailscale::tailscale::{self, TailnetUser};
use nss_tailscale::uid;

/// Refresh cadence. Match the in-process cache TTL (5s) — anything faster is
/// wasted tailscaled traffic, anything slower lets the NSS in-process cache
/// expire between writes.
const SYNC_INTERVAL: Duration = Duration::from_secs(5);

fn main() {
    eprintln!("tailscale-nss-syncd starting (interval = {:?})", SYNC_INTERVAL);

    loop {
        tick();
        thread::sleep(SYNC_INTERVAL);
    }
}

fn tick() {
    let users = match tailscale::fetch_uncached() {
        Ok(u) => u,
        Err(e) => {
            eprintln!("tailscale-nss-syncd: tailscaled fetch failed: {e:?}");
            return;
        }
    };

    if let Err(e) = file_cache::write(&users) {
        eprintln!("tailscale-nss-syncd: cache write failed: {e}");
        // Don't return — still try mkhome below. The cache failure is
        // unrelated to the home-dir creation success path.
    }

    for user in &users {
        if let Err(e) = ensure_home(user) {
            eprintln!(
                "tailscale-nss-syncd: ensure_home for {} failed: {e}",
                user.email
            );
        }
    }
}

/// Make sure `/home/<name>` exists, owned by the synthesized UID/GID, with
/// `/etc/skel` content seeded on first creation.
///
/// We deliberately don't `chown` an *existing* home dir — that's the user's
/// territory now. Once created, hands off.
fn ensure_home(user: &TailnetUser) -> std::io::Result<()> {
    let name = user.unix_name();
    if name.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty username",
        ));
    }
    let home = Path::new("/home").join(&name);
    if home.exists() {
        return Ok(());
    }

    fs::create_dir_all(&home)?;

    let id = uid::for_email(&user.email);
    chown_recursive(&home, id, id)?;
    fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;

    // Best-effort skel copy. We don't care if /etc/skel is missing or empty;
    // the user will populate dotfiles via `home-manager` anyway.
    let skel = Path::new("/etc/skel");
    if skel.is_dir() {
        if let Err(e) = copy_tree(skel, &home, id) {
            eprintln!(
                "tailscale-nss-syncd: skel copy for {} hit an error: {e}",
                user.email
            );
        }
    }
    Ok(())
}

/// Walk `src` and re-create the same tree under `dst`, applying ownership.
/// Plain files only — anything weirder (devices, sockets) is silently skipped.
fn copy_tree(src: &Path, dst: &Path, owner: u32) -> std::io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let s = entry.path();
        let d = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            fs::create_dir_all(&d)?;
            chown_one(&d, owner, owner)?;
            copy_tree(&s, &d, owner)?;
        } else if ft.is_file() {
            fs::copy(&s, &d)?;
            chown_one(&d, owner, owner)?;
        }
        // Symlinks, sockets, fifos in /etc/skel are out of scope for now.
    }
    Ok(())
}

fn chown_one(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    let cpath = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(std::io::Error::other)?;
    // `chown(path, uid, gid)`. We're root in the daemon, so it's a single
    // syscall. Mode 0 isn't passed; ownership only.
    let r = unsafe { libc::chown(cpath.as_ptr(), uid, gid) };
    if r != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn chown_recursive(root: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    chown_one(root, uid, gid)?;
    if root.is_dir() {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let p = entry.path();
            if entry.file_type()?.is_dir() {
                chown_recursive(&p, uid, gid)?;
            } else {
                chown_one(&p, uid, gid)?;
            }
        }
    }
    Ok(())
}
