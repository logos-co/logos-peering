# libpeering against the logos-protocol plain package it is given: this flake's,
# or a consumer's own (liblogos builds it against its runtime's protocol).
{ pkgs, logosProtocol, withTests ? true }:

let
  lib = pkgs.lib;
  deps = [ pkgs.openssl pkgs.nlohmann_json pkgs.libblake3 pkgs.boost logosProtocol ];
in
pkgs.stdenv.mkDerivation {
  pname = "logos-libpeering";
  version = "0.1.0";
  src = lib.cleanSourceWith {
    src = ../.;
    filter = path: type: !(lib.hasPrefix (toString ../modules) (toString path));
  };
  nativeBuildInputs = [ pkgs.cmake pkgs.ninja pkgs.pkg-config ];
  buildInputs = deps ++ lib.optional withTests pkgs.gtest;
  propagatedBuildInputs = deps;
  cmakeFlags = [ "-DLOGOS_PEERING_BUILD_TESTS=${if withTests then "ON" else "OFF"}" ];
  doCheck = withTests;
}
