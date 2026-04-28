//! Side-car daemon for the `tailscale-nss` plugin.
//!
//! Runs as root. On every tick ([`SYNC_INTERVAL`]) it:
//!
//!   1. Asks tailscaled for the current peer list.
//!   2. If the set changed since the last successful tick, atomically
//!      writes it to `/run/tailscale-nss/users.json`. Skipping unchanged
//!      writes keeps the file's mtime stable so the plugin's mtime-based
//!      staleness check doesn't churn.
//!   3. For each synthesized user, ensures `/home/<name>` exists with the
//!      right ownership — Tailscale SSH won't create the home dir, and
//!      `pam_mkhomedir` doesn't fire when sshd is `UsePAM no`, so we do
//!      it here. Idempotent: a `stat` on a present dir is microseconds.
//!
//! Failure handling: log to stderr, continue. The daemon should never
//! exit on transient errors — s6 would restart us, but the no-restart
//! path is faster and avoids log spam.

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::thread;
use std::time::Duration;

use nss_tailscale::file_cache;
use nss_tailscale::tailscale::{self, TailnetUser};

/// Refresh cadence. Match the in-process cache TTL — anything faster is
/// wasted tailscaled traffic, anything slower lets the in-process cache
/// expire between writes.
const SYNC_INTERVAL: Duration = Duration::from_secs(5);

fn main() {
    eprintln!("tailscale-nss-syncd starting (interval = {:?})", SYNC_INTERVAL);

    let mut last_emails: Option<Vec<String>> = None;
    loop {
        last_emails = tick(last_emails);
        thread::sleep(SYNC_INTERVAL);
    }
}

/// One poll cycle. Returns the emails written so the next call can compare
/// and skip the file write when nothing changed.
fn tick(last_emails: Option<Vec<String>>) -> Option<Vec<String>> {
    let users = match tailscale::fetch_uncached() {
        Ok(u) => u,
        Err(e) => {
            eprintln!("tailscale-nss-syncd: tailscaled fetch failed: {e:?}");
            return last_emails;
        }
    };

    let emails: Vec<String> = users.iter().map(|u| u.email.clone()).collect();
    let unchanged = last_emails.as_ref() == Some(&emails);

    if !unchanged {
        if let Err(e) = file_cache::write(&users) {
            eprintln!("tailscale-nss-syncd: cache write failed: {e}");
            // Fall through to home-dir maintenance regardless — they're
            // independent paths.
        }
    }

    for user in &users {
        if let Err(e) = ensure_home(user) {
            eprintln!("tailscale-nss-syncd: ensure_home for {} failed: {e}", user.email);
        }
    }

    Some(emails)
}

/// Make sure `/home/<name>` exists, owned by the synthesized UID/GID,
/// with `/etc/skel` content seeded on first creation.
///
/// We deliberately don't `chown` an *existing* home dir — that's the
/// user's territory now. Once created, hands off.
fn ensure_home(user: &TailnetUser) -> std::io::Result<()> {
    let home = Path::new("/home").join(&user.unix_name);
    if home.exists() {
        return Ok(());
    }

    fs::create_dir_all(&home)?;
    chown(&home, user.uid, user.uid)?;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;

    // Best-effort skel copy. We don't care if /etc/skel is missing or
    // empty; the user populates dotfiles via home-manager anyway.
    let skel = Path::new("/etc/skel");
    if skel.is_dir() {
        if let Err(e) = copy_tree(skel, &home, user.uid) {
            eprintln!("tailscale-nss-syncd: skel copy for {} hit an error: {e}", user.email);
        }
    }
    Ok(())
}

/// Recursively copy plain files and directories from `src` into `dst`,
/// chowning each created entry to `owner:owner`. Symlinks/devices/sockets
/// in /etc/skel are out of scope — uncommon, and worth a separate pass if
/// they ever matter.
fn copy_tree(src: &Path, dst: &Path, owner: u32) -> std::io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let s = entry.path();
        let d = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            fs::create_dir_all(&d)?;
            chown(&d, owner, owner)?;
            copy_tree(&s, &d, owner)?;
        } else if ft.is_file() {
            fs::copy(&s, &d)?;
            chown(&d, owner, owner)?;
        }
    }
    Ok(())
}

fn chown(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    let cpath = CString::new(path.as_os_str().as_encoded_bytes()).map_err(std::io::Error::other)?;
    // We're root in the daemon, so this is a single syscall.
    let r = unsafe { libc::chown(cpath.as_ptr(), uid, gid) };
    if r != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
