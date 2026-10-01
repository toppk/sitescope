{
  description = "sitescope: small health monitor and status page for a few hosts";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      packages.${system}.default = pkgs.callPackage ./nix/package.nix {
        version = self.shortRev or self.dirtyShortRev or "dev";
      };

      nixosModules.default = import ./nix/module.nix self;

      checks.${system} = import ./nix/checks.nix { inherit self nixpkgs pkgs; };

      devShells.${system}.default = pkgs.mkShell {
        packages = [
          pkgs.go
          pkgs.gopls
          pkgs.pandoc
        ];
      };
    };
}
