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
  vendorHash = "sha256-1Yg/116jaWm7yUx59XP43Aswv/8PpDt4r+YI9EKK5/0=";
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
