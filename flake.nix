{
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
    with nixpkgs.legacyPackages.${system};
    {
      devShell = mkShell {
        packages = [
          go
        ];
      };
    });
}
