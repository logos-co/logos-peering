{
  description = "Logos peering: runtime identity, pairing and routes between Logos instances";

  inputs.logos-nix.url = "github:logos-co/logos-nix";
  inputs.nixpkgs.follows = "logos-nix/nixpkgs";
  # Builds the two bundled modules. Its logos-protocol (tls_tcp and the lp_*
  # C ABI) is the one libpeering compiles against too.
  inputs.logos-module-builder.url = "github:logos-co/logos-module-builder/feat/peering";
  inputs.logos-module-builder.inputs.logos-nix.follows = "logos-nix";
  inputs.logos-protocol.follows = "logos-module-builder/logos-protocol";
  # The host process library logos_host_remote is built on.
  inputs.logos-module-loader-qt.url = "github:logos-co/logos-module-loader-qt/feat/peering";
  inputs.logos-module-loader-qt.inputs.logos-nix.follows = "logos-nix";
  inputs.logos-module-loader-qt.inputs.logos-protocol.follows = "logos-module-builder/logos-protocol";
  inputs.logos-module-loader-qt.inputs.logos-cpp-sdk.follows = "logos-module-builder/logos-cpp-sdk";
  inputs.logos-module-loader-qt.inputs.logos-plugin-qt.follows = "logos-module-builder/logos-plugin-qt";

  outputs = { self, nixpkgs, logos-nix, logos-module-builder, logos-protocol, logos-module-loader-qt }:
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

      libpeering = forAllSystems ({ pkgs, system }: import ./nix/libpeering.nix {
        inherit pkgs;
        logosProtocol = logos-protocol.packages.${system}.logos-protocol-plain;
      });

      hostRemote = forAllSystems ({ pkgs, system }: pkgs.stdenv.mkDerivation {
        pname = "logos-host-remote";
        version = "0.1.0";
        src = libpeering.${system}.src;
        nativeBuildInputs = [ pkgs.cmake pkgs.ninja pkgs.pkg-config ];
        buildInputs = libDeps pkgs;
        cmakeFlags = [
          "-DLOGOS_PEERING_BUILD_TESTS=OFF"
          "-DLOGOS_MODULE_LOADER_QT_ROOT=${logos-module-loader-qt.packages.${system}.logos-module-loader-qt-lib}"
        ];
        postInstall = "rm -rf $out/lib $out/include";
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
          (if output == "default" then name
           else if lib.hasPrefix "${name}-" output then output
           else "${name}-${output}") drv)
          (module.packages.${system} or { });
    in
    {
      packages = forAllSystems ({ system, ... }:
        { libpeering = libpeering.${system}; default = libpeering.${system};
          logos_host_remote = hostRemote.${system}; }
        // modulePackages "peering_identity" identityModule system
        // modulePackages "peering_module" peeringModule system);

      checks = forAllSystems ({ system, ... }: {
        libpeering = libpeering.${system};
        logos_host_remote = hostRemote.${system};
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
