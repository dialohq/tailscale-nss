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
        default = self.packages.${pkgs.system}.tailscale-nss;

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
