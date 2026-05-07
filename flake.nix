{
  inputs = {
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      fenix,
      flake-utils,
      nixpkgs,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:

      let
        crossTarget = "aarch64-unknown-linux-musl";
        crossToolchain =
          with fenix.packages.${system};
          combine [
            stable.cargo
            stable.rustc
            targets.${crossTarget}.stable.rust-std
          ];
        nativeToolchain = fenix.packages.${system}.stable.toolchain;
        pkgs = nixpkgs.legacyPackages.${system};
        pkgsCross = nixpkgs.legacyPackages.${system}.pkgsCross.aarch64-multiplatform-musl;
        nativePlatform = pkgs.makeRustPlatform {
          cargo = nativeToolchain;
          rustc = nativeToolchain;
        };
        crossPlatform = pkgs.makeRustPlatform {
          cargo = crossToolchain;
          rustc = crossToolchain;
        };
        commonArgs = {
          pname = "hs-gen";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
        };
      in
      {
        packages = {
          # Native build — used by `nix run .#`
          default = nativePlatform.buildRustPackage commonArgs;

          # Cross-compiled aarch64-unknown-linux-musl static binary
          cross = crossPlatform.buildRustPackage (
            commonArgs
            // {
              CARGO_BUILD_TARGET = crossTarget;
              CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER =
                "${pkgsCross.stdenv.cc}/bin/${pkgsCross.stdenv.cc.targetPrefix}cc";
              nativeBuildInputs = [ pkgsCross.stdenv.cc ];
            }
          );

          doc =
            let
              apiDocs = nativePlatform.buildRustPackage {
                pname = "hs-gen-rustdoc";
                version = "0.1.0";
                dontCheck = true;
                cargoLock.lockFile = ./Cargo.lock;
                src = ./.;
                buildPhase = "cargo doc --offline --no-deps";
                installPhase = ''
                  mkdir -p $out
                  cp -a target/doc/. $out/
                '';
              };
              guideDocs = pkgs.stdenv.mkDerivation {
                name = "hs-gen-guide";
                src = ./docs;
                nativeBuildInputs = [ pkgs.mdbook ];
                buildPhase = "mdbook build";
                installPhase = "cp -r book $out";
              };
            in
            pkgs.runCommand "hs-gen-doc" { } ''
              mkdir -p $out/guide $out/api
              cp -r ${guideDocs}/. $out/guide/
              cp -r ${apiDocs}/. $out/api/
            '';
        };

        devShells = {
          default = pkgs.mkShell {
            buildInputs = [
              (fenix.packages.${system}.stable.withComponents [
                "cargo"
                "clippy"
                "rust-src"
                "rustc"
                "rustfmt"
              ])
            ]
            ++ (with pkgs; [
              tlaps
              tlaplus18
              mdbook

              # Available for integration with other services; not used by hs-gen itself
              openbao
              dex
            ]);

            shellHook = ''
              export CARGO_HOME="$PWD/.cargo"
              export PATH="$CARGO_HOME/bin:$PATH"
              mkdir -p .cargo
              echo '*' > .cargo/.gitignore
              echo "hs-gen dev shell ready"
            '';
          };
        };
      }
    );
}
