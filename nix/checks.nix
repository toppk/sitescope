{
  self,
  nixpkgs,
  pkgs,
}:
let
  eval =
    name: extra:
    (nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        self.nixosModules.default
        {
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
          };
          system.stateVersion = "26.05";
          networking.hostName = name;
        }
        extra
      ];
    }).config;

  hub = eval "hub" {
    services.sitescope = {
      enable = true;
      role = "hub";
      agent = {
        enable = true;
        listenAddress = "10.0.0.2";
      };
      environmentFile = "/var/lib/sitescope-secrets/env";
      settings.alerts = {
        enabled = true;
        from = "sitescope@example.org";
        to = [ "ops@example.org" ];
      };
    };
  };

  agent = eval "agent" {
    services.postfix.enable = true;
    services.knot.enable = true;
    services.sitescope = {
      enable = true;
      role = "agent";
      listenAddress = "10.0.0.3";
    };
  };

  unit = cfg: name: cfg.systemd.units."${name}.service".unit;

  # each line must appear in the generated unit file
  expect =
    name: file: lines:
    pkgs.runCommand "sitescope-${name}" { } ''
      ${pkgs.lib.concatMapStrings (l: ''
        grep -qF -- ${pkgs.lib.escapeShellArg l} ${file}/* || { echo "missing in ${name}: ${l}"; exit 1; }
      '') lines}
      touch $out
    '';
in
{
  package = self.packages.x86_64-linux.default;

  module-hub = expect "hub" (unit hub "sitescope") [
    "User=sitescope"
    "StateDirectory=sitescope"
    "RuntimeDirectory=sitescope"
    "SupplementaryGroups=sitescope-admin"
    "LimitMEMLOCK=1M"
    "LimitCORE=0"
    "MemoryMax=64M"
    "ProtectSystem=strict"
    "NoNewPrivileges=true"
    "RestrictAddressFamilies=AF_UNIX"
    "Restart=on-failure"
    "EnvironmentFile=/var/lib/sitescope-secrets/env"
  ];

  module-hub-agent = expect "hub-agent" (unit hub "sitescope-agent") [
    "User=sitescope-agent"
    "MemoryMax=32M"
  ];

  module-agent = expect "agent" (unit agent "sitescope-agent") [
    "User=sitescope-agent"
    "AmbientCapabilities=CAP_NET_ADMIN"
    "CapabilityBoundingSet=CAP_NET_ADMIN"
    "SupplementaryGroups=postdrop"
    "SupplementaryGroups=knot"
    "RestrictAddressFamilies=AF_NETLINK"
    "MemoryMax=32M"
    "ProtectHome=true"
    "PrivateTmp=true"
  ];

  # the agent host runs no hub, and the generated config carries the wiring
  module-agent-config =
    assert !(agent.systemd.services ? sitescope);
    let
      s = agent.services.sitescope.settings;
    in
    assert s.agent.listen == "10.0.0.3:9105" && s.agent.postfix && s.agent.knot;
    assert hub.services.sitescope.settings.hub.listen == "127.0.0.1:8470";
    pkgs.emptyFile;
}
