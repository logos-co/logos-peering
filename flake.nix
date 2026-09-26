{
  description = "Logos peering: runtime identity, pairing and routes between Logos instances";

  inputs.logos-nix.url = "github:logos-co/logos-nix";
  inputs.nixpkgs.follows = "logos-nix/nixpkgs";
  # Builds the two bundled modules. Its logos-protocol (tls_tcp and the lp_*
  # C ABI) is the one libpeering compiles against too.
  inputs.logos-module-builder.url = "github:logos-co/logos-module-builder/feat/peering";
  inputs.logos-module-builder.inputs.logos-nix.follows = "logos-nix";
  inputs.logos-protocol.follows = "logos-module-builder/logos-protocol";

  outputs = { self, nixpkgs, logos-nix, logos-module-builder, logos-protocol }:
    let
      lib = nixpkgs.lib;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: lib.genAttrs systems (system: f {
        inherit system;
        pkgs = import nixpkgs { inherit system; };
      });
      libDeps = pkgs: [
        pkgs.openssl pkgs.nlohmann_json pkgs.libblake3 pkgs.boost
        logos-protocol.packages.${pkgs.stdenv.hostPlatform.system}.logos-protocol-plain
      ];

      libpeering = forAllSystems ({ pkgs, ... }: pkgs.stdenv.mkDerivation {
        pname = "logos-libpeering";
        version = "0.1.0";
        src = lib.cleanSourceWith {
          src = ./.;
          filter = path: type: !(lib.hasPrefix (toString ./modules) (toString path));
        };
        nativeBuildInputs = [ pkgs.cmake pkgs.ninja pkgs.pkg-config ];
        buildInputs = libDeps pkgs ++ [ pkgs.gtest ];
        propagatedBuildInputs = libDeps pkgs;
        cmakeFlags = [ "-DLOGOS_PEERING_BUILD_TESTS=ON" ];
        doCheck = true;
      });

      # libpeering as the builder's externalLibInputs expect a flake.
      peeringLib = { packages = lib.mapAttrs (system: drv: { default = drv; }) libpeering; };

      identityModule = logos-module-builder.lib.mkLogosModule {
        src = ./modules/peering_identity;
        configFile = ./modules/peering_identity/metadata.json;
        externalLibInputs = { logos_peering = peeringLib; };
      };

      peeringModule = logos-module-builder.lib.mkLogosModule {
        src = ./modules/peering_module;
        configFile = ./modules/peering_module/metadata.json;
        flakeInputs = { peering_identity = identityModule; };
        externalLibInputs = { logos_peering = peeringLib; };
      };

      modulePackages = name: module: system:
        lib.mapAttrs' (output: drv: lib.nameValuePair
          (if output == "default" then name else "${name}-${output}") drv)
          (module.packages.${system} or { });
    in
    {
      packages = forAllSystems ({ system, ... }:
        { libpeering = libpeering.${system}; default = libpeering.${system}; }
        // modulePackages "peering_identity" identityModule system
        // modulePackages "peering_module" peeringModule system);

      checks = forAllSystems ({ system, ... }: {
        libpeering = libpeering.${system};
        peering_identity = identityModule.packages.${system}.default;
        peering_module = peeringModule.packages.${system}.default;
      });

      devShells = forAllSystems ({ pkgs, ... }: {
        default = pkgs.mkShell {
          packages = [ pkgs.cmake pkgs.ninja pkgs.pkg-config pkgs.gtest ] ++ libDeps pkgs;
        };
      });
    };
}
