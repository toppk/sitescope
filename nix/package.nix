{
  lib,
  buildGoModule,
  version,
}:
buildGoModule {
  pname = "sitescope";
  inherit version;
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../VERSION
      ../go.mod
      ../go.sum
      ../main.go
      ../internal
      ../testdata
    ];
  };
  vendorHash = "sha256-8nlEbKeJPXQZxb6Ohz7y4BTMtS9RgXTgtGIZWwyNKeY=";
  env.CGO_ENABLED = 0;
  flags = [ "-trimpath" ];
  ldflags = [
    "-s"
    "-w"
    "-X main.version=${version}"
  ];
  meta = {
    description = "Health monitor with status page, email alerts and a locked credential vault";
    mainProgram = "sitescope";
    platforms = lib.platforms.linux;
  };
}
