{ config, options, pkgs, lib, utils, name, deploymentName, uuid, ... }:

with lib;

let

  machine = mkOptionType {
    name = "a machine";
    check = x: x._type or "" == "machine";
    merge = mergeOneOption;
  };

  deployment = config.deployment;
  # e.g. vz-nix-01234567 (15 chars)
  shortUuid = builtins.substring 0 8 uuid;
  instanceId = "${name}.${deploymentName}.${shortUuid}";

in

{

  options = {

    deployment.container = {

      targetHost = mkOption {
        type = types.either types.str machine;
        apply = x: if builtins.isString x then x else "__machine-" + x._name;
        description = ''
          The GNU/Linux machine with Nix and Systemd on which this container is to be instantiated.
          An ordinal hostname, a IP address or a machine in this deployment can be specified.
          Default value is `deployment.targetHost` or localhost.
        '';
      };

      targetUser = mkOption {
        type = types.str;
        default = "root";
        description = ''
          Host user: the ssh user name of the machine on which this container is to be instantiated.
          This user must be able to login and run 'sudo' without password.
          You might consider tweaking `security.sudo.extraRules` of the host.
          If special value "" is set, login as the current user who runs NixOps.
        '';
      };

      autoStart = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Start this machine at boot time of the host automatically.
          Note that `deployment.keys` are not refilled; you should `send-keys` by hand if not persisted.
          Additionally, you need to set `boot.enableContainers = true;`
          or `systemd.targets."multi-user".wants = [ "machines.target" ];` on the host
          to be in effect.
        '';
      };

      nspawn = mkOption {
        type =
          (import <nixpkgs/nixos/modules/system/boot/systemd-nspawn.nix> { inherit config lib pkgs; })
            .options.systemd.nspawn.type.functor.wrapped;
        default = {};
        description = ''
          systemd-nspawn extra config
        '';
      };

      service = mkOption {
        type = types.unspecified;
          /* (import <nixpkgs/nixos/modules/system/boot/systemd.nix> { inherit config pkgs lib utils; })
            .options.systemd.services.type.functor.wrapped; */
        default = {};
        description = ''
          systemd-nspawn@.service extra config
        '';
      };

      preDeploy = mkOption {
        type = types.nullOr types.lines;
        default = null;
        description = ''
          The commands run on the host prior to every machine deployment.
        '';
      };

      preDestroy = mkOption {
        type = types.nullOr types.lines;
        default = null;
        description = ''
          The commands run on the host prior to the destroy of the machine.
        '';
      };

      instanceId = mkOption {
        type = types.str;
        description = ''
          The instance ID of the NixOps container. This is set by NixOps.
        '';
      };

    };

  };

  config = mkIf (config.deployment.targetEnv == "nixops-container") {

    # Options default
    deployment.container.targetHost = mkDefault config.deployment.targetHost;
    deployment.container.instanceId = instanceId;

    # workaround for undefined option (uses DefaultStartLimitIntervalSec)
    /* deployment.container.service =
      mkIf (!(options.systemd.services.type.functor.wrapped.getSubOptions []).startLimitIntervalSec.isDefined)
        { startLimitIntervalSec = mkDefault 10; }; */

    boot.isContainer = true;

    systemd.nspawn.${ instanceId } = mkMerge [{

      environment = {
        DEPLOYMENT = deploymentName;
        DEPLOYMENT_UUID = uuid;
        INSTANCE_ID = instanceId;
        PATH = "${pkgs.coreutils}/bin:${pkgs.utillinux}/bin:${pkgs.openresolv}/bin";
      };

      execConfig = {
        NotifyReady = "yes";
        Hostname = name;
        ResolvConf = "off";
        Timezone = "off";
        LinkJournal = "try-guest";
      };

      bindReadOnly = {
        # Mount Nix
        "/nix/store" = {};
        "/nix/var/nix/db" = {};
        "/nix/var/nix/daemon-socket" = {};
      };

      bind = {
        # Manage the deps within the containers on the host
        "/nix/var/nix/profiles" =
          { source = "/nix/var/nix/profiles/per-container/${instanceId}"; };
        "/nix/var/nix/gcroots" =
          { source = "/nix/var/nix/gcroots/per-container/${instanceId}"; };
      };

      networkConfig = {
        Private = "yes";
        #Zone = "nix-${ shortUuid }"; # optional?
        #Zone = "nix-default";
      };

    } deployment.container.nspawn ];

    systemd.services."systemd-nspawn@${ instanceId }" = mkMerge [{
      #enable = false; # should not be run in the container
      unitConfig.ConditionHost = "!${ name }";

      # taken from the stock systemd-nspawn@.service
      description = mkDefault "NixOps Container '${ name }' of the deployment '${ deploymentName }'";
      documentation = [ "man:systemd-nspawn.service(1)" ];
      partOf = [ "machines.target" ];
      before = [ "machines.target" ];
      after = [ "network.target" "systemd-resolved.service" ];
      wants = [ "network.target" ]; # if config.autoStart
      # wantedBy = [ "machines.target" ];
      # unitConfig.WantedBy = if deployment.container.autoStart then [ "machines.target" ] else [];
      unitConfig.RequiresMountsFor = "/var/lib/machines";
      serviceConfig = {
        KillMode = "mixed";
        Type = "notify";
        RestartForceExitStatus = 133;
        SuccessExitStatus = 133;
        WatchdogSec = "3min";
        Slice = "machine.slice";
        Delegate = "yes";
        TasksMax = 16384;

        # Enforce a strict device policy, similar to the one nspawn configures when it
        # allocates its own scope unit. Make sure to keep these policies in sync if you
        # change them!
        DevicePolicy = "closed";
        DeviceAllow = [
          "/dev/net/tun rwm"
          "char-pts rw"

          # nspawn itself needs access to /dev/loop-control and /dev/loop, to implement
          # the --image= option. Add these here, too.
          "/dev/loop-control rw"
          "block-loop rw"
          "block-blkext rw"

          # nspawn can set up LUKS encrypted loopback files, in which case it needs
          # access to /dev/mapper/control and the block devices /dev/mapper/*.
          "/dev/mapper/control rw"
          "block-device-mapper rw"
        ];
      };

      preStart = ''
        root=/var/lib/machines/${instanceId}
        mkdir -p $root /nix/var/nix/{profiles,gcroots}/per-container/${instanceId}
        chmod 0700 /var/lib/machines /nix/var/nix/{profiles,gcroots}/per-container
      '';
      # ^ The per-container directories are restricted to prevent users on
      # the host from messing with guest users who happen to have the
      # same uid.

      # replaced to the NixOS toplevel out path by `system.extraSystemBuilderCmds` below
      scriptArgs = "@systemConfig@";
      script = ''
        # stop launch if on the same container...
        [ $1 = @systemConfig@ ] && { echo Cannot start the container in itself >&2; exit 1; }
        exec ${pkgs.systemd}/bin/systemd-nspawn --machine=${instanceId} --keep-unit $1/init
      '';

      postStop = ''
        machinectl terminate ${instanceId}
      '';

    } deployment.container.service ];

    system.extraSystemBuilderCmds = ''
      cp $out/etc/systemd/system/systemd-nspawn@${instanceId}.service $out
      substituteInPlace $out/systemd-nspawn@${instanceId}.service --subst-var-by systemConfig $out
    '';

    networking.useNetworkd = true;
    systemd.network.networks."50-eth0-dhcp" = {
      matchConfig.Name = "eth0";
      DHCP = "yes";
      dhcpConfig = {
        #UseMTU = true;
        #UseDomains = "route";
        #UserClass = [ instanceId deploymentName shortUuid ]; # BUG: not sent in systemd 239
        VendorClassIdentifier = "${instanceId} ${deploymentName} ${shortUuid}";
      };
      #networkConfig.IPv6AcceptRA = false;
    };

    boot.postBootCommands = "${pkgs.iproute}/bin/ip link set dev host0 name eth0;";
  };

}
