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

Scaffold. `getpwnam` / `getpwuid` / `getpwent` work end-to-end against a
local tailscaled. **Not yet hardened**:

- [ ] In-memory cache (currently every NSS lookup hits tailscaled — fine for
      a small tailnet, but `ls -l` on a busy directory will fan out)
- [ ] Background poller daemon to decouple NSS latency from network latency
- [ ] Group membership (only "primary group per user" today)
- [ ] PAM mkhomedir integration to auto-create `/home/<user>` on first login
- [ ] Failure-mode tests (tailscaled down, slow, returning garbage)

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
