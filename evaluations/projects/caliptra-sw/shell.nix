# Licensed under the Apache-2.0 license
# SPDX-License-Identifier: Apache-2.0
{ pkgs ? import <nixpkgs> {} }:
let
  rustToolchain = pkgs.rust-bin.stable.latest.default.override {
    extensions = [ "rust-src" "llvm-tools-preview" ];
    targets = [ "riscv32imc-unknown-none-elf" ];
  };
in
pkgs.mkShell {
  name = "caliptra-sw-benchmark-shell";
  nativeBuildInputs = [
    rustToolchain
    pkgs.git
    pkgs.pkg-config
    pkgs.openssl
    pkgs.libusb1
    pkgs.gcc
    pkgs.taplo
    pkgs.cargo-nextest
  ];

  shellHook = ''
    export PKG_CONFIG_PATH="${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.libusb1.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    export OPENSSL_DIR="${pkgs.openssl.dev}"
    export OPENSSL_LIB_DIR="${pkgs.openssl.out}/lib"
    export OPENSSL_INCLUDE_DIR="${pkgs.openssl.dev}/include"
    export CPATH="${pkgs.openssl.dev}/include:${pkgs.libusb1.dev}/include:${pkgs.glibc.dev}/include''${CPATH:+:$CPATH}"
    export LIBRARY_PATH="${pkgs.openssl.out}/lib:${pkgs.libusb1.out}/lib:${pkgs.glibc}/lib''${LIBRARY_PATH:+:$LIBRARY_PATH}"
  '';
}
