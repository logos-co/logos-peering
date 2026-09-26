{
  description = "Logos peering: runtime identity, pairing and routes between Logos instances";

  inputs.logos-nix.url = "github:logos-co/logos-nix";
  inputs.nixpkgs.follows = "logos-nix/nixpkgs";
  # tls_tcp and the lp_* C ABI the service speaks.
  inputs.logos-protocol.url = "github:logos-co/logos-protocol/feat/peering";
  inputs.logos-protocol.inputs.logos-nix.follows = "logos-nix";

  outputs = { self, nixpkgs, logos-nix, logos-protocol }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f {
        inherit system;
        pkgs = import nixpkgs { inherit system; };
      });
      libDeps = pkgs: [
        pkgs.openssl pkgs.nlohmann_json pkgs.libblake3 pkgs.boost
        logos-protocol.packages.${pkgs.stdenv.hostPlatform.system}.logos-protocol-plain
      ];
    in
    {
      packages = forAllSystems ({ pkgs, ... }: rec {
        libpeering = pkgs.stdenv.mkDerivation {
          pname = "logos-libpeering";
          version = "0.1.0";
          src = pkgs.lib.cleanSource ./.;
          nativeBuildInputs = [ pkgs.cmake pkgs.ninja pkgs.pkg-config ];
          buildInputs = libDeps pkgs ++ [ pkgs.gtest ];
          propagatedBuildInputs = libDeps pkgs;
          cmakeFlags = [ "-DLOGOS_PEERING_BUILD_TESTS=ON" ];
          doCheck = true;
        };
        default = libpeering;
      });

      checks = forAllSystems ({ system, ... }: {
        libpeering = self.packages.${system}.libpeering;
      });

      devShells = forAllSystems ({ pkgs, ... }: {
        default = pkgs.mkShell {
          packages = [ pkgs.cmake pkgs.ninja pkgs.pkg-config pkgs.gtest ] ++ libDeps pkgs;
        };
      });
    };
}
