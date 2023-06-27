{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    packages = with pkgs; [ rustc cargo gcc rustfmt clippy ];
    name = "rust-env";
}
