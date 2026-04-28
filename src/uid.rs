//! Deterministic UID/GID derivation from a tailnet email.
//!
//! Stability is non-negotiable: a user's UID must be the *same* every time
//! the container starts (different vast.ai/runpod allocations, restarts of a
//! persistent volume), or `chown` storms ruin every persisted home dir.
//!
//! We hash the email and fold into the namespace
//!     [`config::uid_base()`, `i32::MAX`]
//! to keep clear of the OS reserved range (0..1000), the home-manager
//! convention range (1000..100000-ish), and to stay positive in `i32`-typed
//! syscalls (some kernels reject UIDs above `i32::MAX` for compatibility).
//!
//! Collisions are theoretically possible but at ~1 in 2 billion the practical
//! collision probability for a tailnet of N users is N²/2³¹, i.e. 0.5% for
//! N=10000. Add real collision detection if your tailnet ever grows that big.

use crate::config;

/// Stable UID for a tailnet email. Same input → same output, forever.
pub fn for_email(email: &str) -> u32 {
    let h = fnv1a64(email.as_bytes());
    let span = (i32::MAX as u32) - config::uid_base();
    config::uid_base() + ((h as u32) % span)
}

/// FNV-1a 64-bit. Tiny, dependency-free, deterministic, well-distributed
/// for short strings. We don't need a cryptographic hash here — just a
/// stable, well-spread integer from a string.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_across_calls() {
        assert_eq!(for_email("alice@dialo.ai"), for_email("alice@dialo.ai"));
    }

    #[test]
    fn different_users_different_uids() {
        assert_ne!(for_email("alice@dialo.ai"), for_email("bob@dialo.ai"));
    }

    #[test]
    fn lands_in_safe_range() {
        let uid = for_email("alice@dialo.ai");
        assert!(uid >= config::DEFAULT_UID_BASE);
        assert!(uid < i32::MAX as u32);
    }

    /// Lock the FNV-1a output for known emails. The CI integration test
    /// asserts `getent passwd alice` returns *exactly* this UID
    /// (`.github/workflows/ci.yml`); changing the constants here without
    /// updating both fails fast and loudly. If you ever want to tune the
    /// hash or the UID base, update both call sites in the same PR.
    #[test]
    fn pinned_uids_for_ci_fixtures() {
        assert_eq!(for_email("alice@dialo.ai"), 109_535_949);
        assert_eq!(for_email("bob@dialo.ai"), 1_110_256_801);
    }
}
