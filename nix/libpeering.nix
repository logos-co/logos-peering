# libpeering against the logos-protocol plain package it is given: this flake's,
# or a consumer's own (liblogos builds it against its runtime's protocol).
# windowsTests: the manifest a Windows runner reads (logos-windows-ci `tests: true`).
{ pkgs, logosProtocol, withTests ? true, windowsTests ? null }:

let
  lib = pkgs.lib;
  isWindows = pkgs.stdenv.hostPlatform.isWindows;
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
  cmakeFlags = [ "-DLOGOS_PEERING_BUILD_TESTS=${if withTests then "ON" else "OFF"}" ]
    # A PE cannot run on the build machine: nothing is discovered or run here.
    ++ lib.optional (withTests && isWindows) "-DCMAKE_GTEST_DISCOVER_TESTS_DISCOVERY_MODE=PRE_TEST";
  doCheck = withTests && !isWindows;
  # A Windows box runs them instead, from the manifest.
  postInstall = lib.optionalString (withTests && isWindows && windowsTests != null) ''
    mkdir -p $out/bin $out/share/logos-tests
    cp logos_peering_tests.exe $out/bin/
    cp ${windowsTests} $out/share/logos-tests/libpeering.json
  '';
}
