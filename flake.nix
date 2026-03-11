{
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
    with nixpkgs.legacyPackages.${system};
    {
      devShells.default = mkShell {
        packages = [
          go
        ];
      };
    });
}
