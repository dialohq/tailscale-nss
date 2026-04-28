{
  description = "NSS plugin that synthesizes UNIX users from a tailnet's peer list";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      # We only ever target Linux: NSS is a glibc thing, no Darwin equivalent.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in {
      packages = forAll (pkgs: {
        # Default is the portable variant — that's what `nix run`,
        # `nix shell`, and CI artifact consumers get out of the box.
        # Nix-native consumers (other flakes) that want the un-patched,
        # nix-store-pinned binary can reference `.tailscale-nss` by name.
        default = self.packages.${pkgs.system}.portable;

        tailscale-nss = pkgs.rustPlatform.buildRustPackage {
          pname = "tailscale-nss";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          # The crate builds to `libnss_tailscale.so`. Glibc looks for
          # `libnss_tailscale.so.2` (with the `.2` SONAME suffix), so install
          # both the unversioned link and the suffixed name.
          postInstall = ''
            mkdir -p $out/lib
            mv $out/lib/libnss_tailscale.so $out/lib/libnss_tailscale.so.2
            ln -s libnss_tailscale.so.2 $out/lib/libnss_tailscale.so
          '';

          meta = {
            description = "NSS plugin synthesizing UNIX users from tailnet peers";
            platforms = systems;
          };
        };

        # Portable variant for non-nix hosts (stock Debian/Ubuntu/Fedora/...).
        #
        # The default `tailscale-nss-syncd` binary has its `PT_INTERP` set to
        # nix's dynamic linker (`/nix/store/...glibc/lib/ld-linux-x86-64.so.2`),
        # which is ideal *inside* nix-based environments — but on a stock
        # Linux box that path doesn't exist and `execve` returns ENOENT.
        # Verified end-to-end against Debian 12: patching the interpreter to
        # `/lib64/ld-linux-x86-64.so.2` is enough on its own (the binary's
        # NEEDED libs — libc.so.6, libgcc_s.so.1 — resolve through the
        # standard `/etc/ld.so.cache` search path with no RPATH gymnastics).
        #
        # The .so is unaffected: shared libraries don't have `PT_INTERP`,
        # they're loaded by whatever process is doing the NSS lookup, so the
        # `default` package's .so is already portable.
        portable = pkgs.runCommandLocal "tailscale-nss-portable" {
          nativeBuildInputs = [ pkgs.patchelf ];
        } ''
          mkdir -p $out/bin $out/lib
          cp -r ${self.packages.${pkgs.system}.tailscale-nss}/lib/. $out/lib/
          cp ${self.packages.${pkgs.system}.tailscale-nss}/bin/tailscale-nss-syncd $out/bin/
          chmod u+w $out/bin/tailscale-nss-syncd
          patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 \
            $out/bin/tailscale-nss-syncd
          chmod a-w $out/bin/tailscale-nss-syncd
        '';
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [ rustc cargo rustfmt clippy rust-analyzer ];
          # Easier ad-hoc testing against a running tailscaled.
          TAILSCALE_NSS_DOMAIN = "dialo.ai";
        };
      });
    };
}
