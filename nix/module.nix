self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.sitescope;
  format = pkgs.formats.json { };
  configFile = format.generate "sitescope.json" cfg.settings;
  runHub = cfg.role == "hub";
  runAgent = cfg.role == "agent" || cfg.agent.enable;
  agentAddr = if cfg.role == "agent" then cfg.listenAddress else cfg.agent.listenAddress;
  agentPort = if cfg.role == "agent" then cfg.port else cfg.agent.port;
  postfix = config.services.postfix;
  knot = config.services.knot;

  hardening = {
    Restart = "on-failure";
    RestartSec = "5s";
    EnvironmentFile = lib.optional (cfg.environmentFile != null) cfg.environmentFile;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    NoNewPrivileges = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    UMask = "0077";
    LimitCORE = 0;
  };
in
{
  options.services.sitescope = {
    enable = lib.mkEnableOption "sitescope";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "sitescope.packages.\${system}.default";
    };

    role = lib.mkOption {
      type = lib.types.enum [
        "hub"
        "agent"
      ];
      description = "hub polls agents, probes, alerts and serves the status page; agent reports local facts.";
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = if cfg.role == "hub" then "127.0.0.1" else "";
      defaultText = lib.literalExpression ''"127.0.0.1" for the hub; required for an agent (its wg0 address)'';
      description = "Address the role's HTTP server binds to. For an agent, the host's wg0 address.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = if cfg.role == "hub" then 8470 else 9105;
      defaultText = lib.literalExpression "8470 for the hub, 9105 for an agent";
    };

    agent = {
      enable = lib.mkEnableOption "an agent next to the hub on the same host";
      listenAddress = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "wg0 address for the hub host's own agent.";
      };
      port = lib.mkOption {
        type = lib.types.port;
        default = 9105;
      };
    };

    adminGroup = lib.mkOption {
      type = lib.types.str;
      default = "sitescope-admin";
      description = "Members may use the hub's control socket (sitescope unlock/lock/status).";
    };

    settings = lib.mkOption {
      type = format.type;
      default = { };
      description = ''
        Freeform JSON config (checks, targets, thresholds, recipients); see README.md.
        Listen addresses, paths and command locations are filled in by the module.
      '';
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        KEY=value file outside the Nix store with SITESCOPE_AGENT_TOKEN (hub and agents)
        and SITESCOPE_HEARTBEAT_URL (hub).
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        assertions = [
          {
            assertion = !runAgent || agentAddr != "";
            message = "services.sitescope: an agent needs its wg0 address (listenAddress, or agent.listenAddress on the hub).";
          }
          {
            assertion = !(cfg.role == "agent" && cfg.agent.enable);
            message = "services.sitescope.agent.enable is for hub hosts; an agent host uses role = \"agent\".";
          }
        ];
      }

      (lib.mkIf runHub {
        services.sitescope.settings.hub = {
          listen = lib.mkDefault "${cfg.listenAddress}:${toString cfg.port}";
          stateDir = "/var/lib/sitescope";
          vault = "/var/lib/sitescope/vault.age";
          controlSocket = "/run/sitescope/control.sock";
          controlGroup = cfg.adminGroup;
          hostname = lib.mkDefault config.networking.hostName;
        };

        users.users.sitescope = {
          isSystemUser = true;
          group = "sitescope";
        };
        users.groups.sitescope = { };
        users.groups.${cfg.adminGroup} = { };

        # operators run `sitescope unlock`, and `sudo -u sitescope sitescope vault ...`
        environment.systemPackages = [ cfg.package ];
        environment.etc."sitescope/config.json".source = configFile;

        systemd.services.sitescope = {
          description = "sitescope hub";
          wantedBy = [ "multi-user.target" ];
          wants = [ "network-online.target" ];
          after = [ "network-online.target" ];
          restartTriggers = [ configFile ];
          environment.GOMEMLIMIT = "40MiB";
          serviceConfig = hardening // {
            ExecStart = "${lib.getExe cfg.package} hub -config ${configFile}";
            User = "sitescope";
            Group = "sitescope";
            SupplementaryGroups = [ cfg.adminGroup ];
            StateDirectory = "sitescope";
            StateDirectoryMode = "0700";
            RuntimeDirectory = "sitescope";
            RuntimeDirectoryMode = "0755";
            CapabilityBoundingSet = "";
            AmbientCapabilities = "";
            RestrictAddressFamilies = [
              "AF_INET"
              "AF_INET6"
              "AF_UNIX"
            ];
            # vault (64 KiB) + passphrase buffers, page-rounded
            LimitMEMLOCK = "1M";
            MemoryMax = "64M";
          };
        };
      })

      (lib.mkIf runAgent {
        services.sitescope.settings.agent = {
          listen = "${agentAddr}:${toString agentPort}";
          systemctl = "${config.systemd.package}/bin/systemctl";
          wg = "${pkgs.wireguard-tools}/bin/wg";
          postfix = lib.mkDefault postfix.enable;
          knot = lib.mkDefault knot.enable;
        }
        // lib.optionalAttrs postfix.enable { postqueue = "${postfix.package}/bin/postqueue"; }
        // lib.optionalAttrs knot.enable { knotc = "${knot.package}/bin/knotc"; };

        users.users.sitescope-agent = {
          isSystemUser = true;
          group = "sitescope-agent";
        };
        users.groups.sitescope-agent = { };

        systemd.services.sitescope-agent = {
          description = "sitescope agent";
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          restartTriggers = [ configFile ];
          environment.GOMEMLIMIT = "20MiB";
          serviceConfig = hardening // {
            ExecStart = "${lib.getExe cfg.package} agent -config ${configFile}";
            User = "sitescope-agent";
            Group = "sitescope-agent";
            SupplementaryGroups =
              lib.optional postfix.enable postfix.setgidGroup ++ lib.optional knot.enable "knot";
            # wg show needs it; nothing else is granted
            AmbientCapabilities = [ "CAP_NET_ADMIN" ];
            CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
            RestrictAddressFamilies = [
              "AF_INET"
              "AF_INET6"
              "AF_UNIX"
              "AF_NETLINK"
            ];
            MemoryMax = "32M";
          };
        };
      })
    ]
  );
}
