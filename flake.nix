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
      fenix,
      flake-utils,
      nixpkgs,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:

      let
        target = "aarch64-unknown-linux-musl";
        toolchain =
          with fenix.packages.${system};
          combine [
            stable.cargo
            stable.rustc
            targets.${target}.stable.rust-std
          ];
        pkgs = nixpkgs.legacyPackages.${system};
        pkgsCross = nixpkgs.legacyPackages.${system}.pkgsCross.aarch64-multiplatform-musl;
        platform = pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        };
      in
      {
        packages = {
          default = platform.buildRustPackage {
            pname = "hs-gen";
            version = "0.1.0";
            src = ./.;

            cargoLock.lockFile = ./Cargo.lock;

            # Cross-compile to aarch64-unknown-linux-musl
            CARGO_BUILD_TARGET = target;
            CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER =
              "${pkgsCross.stdenv.cc}/bin/${pkgsCross.stdenv.cc.targetPrefix}cc";

            # Musl cross-linker as native build input
            nativeBuildInputs = [ pkgsCross.stdenv.cc ];
          };

          doc =
            let
              apiDocs = platform.buildRustPackage {
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
