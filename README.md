# tailscale-nss

A glibc NSS plugin that synthesizes UNIX users from a tailnet's peer list.

When `getpwnam("alice")` is called inside a process whose `/etc/nsswitch.conf`
includes `passwd: files tailscale`, this plugin asks the local `tailscaled`
"is `alice@<your-domain>` on the tailnet?" — and if so, returns a synthetic
`struct passwd` with a stable UID derived from the email. No `useradd`. No
`/etc/passwd` entries. No reconciler.

Inspired by Google's `nss_oslogin`, but backed by Tailscale instead of GCE
metadata, so it works on any host that can run tailscaled.

## Status

Builds clean (rust 1.94, clippy with `-D warnings`), 10 tests pass.

What works:

- [x] `getpwnam` / `getpwuid` / `getpwent` (and group equivalents) via the
      tailscaled local API socket (`/localapi/v0/status`)
- [x] Stable FNV-1a-derived UIDs in `[100000, INT32_MAX)` — same input
      always produces the same UID, so persistent home dirs survive
      container restarts without `chown` storms
- [x] 5s in-process cache (single tailscaled hit serves `ls -l` of an
      N-file directory)
- [x] Graceful degradation: serve last-known-good cache on transient
      failures (tailscaled briefly down)
- [x] Hard 250ms timeout on every tailscaled call (NSS plugins are
      `dlopen`'d into sshd, ls, ps, sudo, login shells — a hung daemon
      must not wedge the host process)
- [x] `panic = "abort"` + Mutex-poisoning recovery (panicking through libc
      via FFI is not safe; we make sure we don't, and recover if we did)
- [x] Hand-rolled HTTP/1.0 over UnixStream (no async runtime baggage in a
      `dlopen`'d plugin)
- [x] Fail-closed on missing `TAILSCALE_NSS_DOMAIN` (won't accidentally
      synthesize every tailnet peer as a UNIX user)
- [x] Failure-mode tests: missing socket / HTTP 500 / malformed JSON /
      slow server exceeding timeout — all return `Err` cleanly, none hang
      or panic

Still outstanding (next pass):

- [ ] Background poller daemon (so the *first* lookup after cache expiry
      also stays under 50ms)
- [ ] Real group membership beyond "primary group per user"
- [ ] PAM `mkhomedir` integration so `/home/<user>` exists on first login
- [ ] Image integration: glibc override to install the `.so` where nix's
      glibc looks for it; `/etc/nsswitch.conf` patch in `remote-devenv.nix`

## Building

```bash
nix build
ls -la result/lib/   # libnss_tailscale.so, libnss_tailscale.so.2
```

## Wiring it into a container

In your image's `/etc/nsswitch.conf`:

```
passwd:    files tailscale
group:     files tailscale
shadow:    files
```

In your image build, install the `.so` where glibc looks. For nix-built
glibc, that's `${pkgs.glibc}/lib/`. For an Ubuntu-base image with the
distro's glibc, symlink into `/lib/x86_64-linux-gnu/`. (Practical detail:
to get the file into nix's glibc lib dir, override glibc with `addNssModules`
or copy the `.so` into a path on `LD_LIBRARY_PATH` for sshd's sub-processes
— see the parent `remote-devenv.nix` for the integration glue.)

Set environment variables on every NSS-using process (typically via the
sshd `Environment=` block or equivalent):

| Var | Default | Required? |
|-----|---------|-----------|
| `TAILSCALE_NSS_DOMAIN` | _(none — failing closed)_ | yes |
| `TAILSCALE_NSS_SOCKET` | `/var/run/tailscale/tailscaled.sock` | no |
| `TAILSCALE_NSS_SHELL` | `/bin/bash` | no |
| `TAILSCALE_NSS_UID_BASE` | `100000` | no |

Without `TAILSCALE_NSS_DOMAIN` set, the plugin returns no users — the safe
default for an NSS module that could otherwise expose every tailnet peer.

## Why this is interesting

The reconciler-loop alternative (poll `tailscale status`, run `useradd` for
each new peer) churns `/etc/passwd` on a clock and creates a window between
"alice joins the tailnet" and "alice can SSH". This plugin makes the answer
to `getpwnam` _live_: alice can SSH the moment she's resolvable on the
tailnet, without ever writing to `/etc/passwd`.

The same trick is what Google's `nss_oslogin` uses for GCE/IAM identities —
this is just the open analog with Tailscale as the IdP bridge.

## License

MIT.
