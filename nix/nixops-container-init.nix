# nix-instantiate 'nixops/nix/nixops-container-init.nix' --eval --argstr uuid uuid -I nixops=$(pwd)/nixops/nix --option system x86_64-linux --argstr name hostname --argstr clientPublicKey key --argstr deploymentName deploy --arg containerAttrs '{}'
# nix-build 'nixops/nix/nixops-container-init.nix' --argstr uuid uuid -I nixops=$(pwd)/nixops/nix --option system x86_64-linux --argstr name hostname --argstr clientPublicKey key --argstr deploymentName deploy --arg containerAttrs '{}'
{ name, deploymentName, uuid, clientPublicKey, containerAttrs }:
let nixos =
  import <nixpkgs/nixos/lib/eval-config.nix> {
    modules = [
      <nixops/resource.nix>
      <nixops/options.nix>
      ({ config, pkgs, ...}: {
        config = {
          deployment.targetEnv = "nixops-container";
          deployment.container = containerAttrs;
          networking.hostName = name;
          users.extraUsers.root.openssh.authorizedKeys.keys = [ clientPublicKey ];

          boot.isContainer = true;
          networking.useDHCP = false;
          networking.useHostResolvConf = false;
          services.openssh.enable = true;
          services.openssh.startWhenNeeded = false;
          services.openssh.extraConfig = "UseDNS no";
        };
      })
    ];
    extraArgs = { inherit name deploymentName uuid; };
  };
in nixos.config.system.build.toplevel
