# -*- coding: utf-8 -*-
import os
import sys
import nixops.util
import platform
import subprocess
import time
import re

from nixops.backends import MachineDefinition, MachineState
from nixops.nix_expr import py2nix
from nixops.util import attr_property, create_key_pair
from nixops.ssh_util import SSHConnectionFailed, SSHCommandFailed

class NixOpsContainerDefinition(MachineDefinition):
    """Definition of a NixOps container machine."""

    @classmethod
    def get_type(cls):
        return "nixops-container"

    def __init__(self, xml, config):
        MachineDefinition.__init__(self, xml, config)
        self.host = config["container"]["targetHost"]
        self.host_user = config["container"]["targetUser"]
        self.pre_deploy_script = config["container"]["preDeploy"]
        self.pre_destroy_script = config["container"]["preDestroy"]

class NixOpsContainerState(MachineState):
    """State of a NixOps container machine."""

    @classmethod
    def get_type(cls):
        return "nixops-container"

    # States saved in state file
    state = nixops.util.attr_property("state", MachineState.MISSING, int)  # override
    private_ipv4 = nixops.util.attr_property("privateIpv4", None)
    host = nixops.util.attr_property("container.targetHost", None) # require destroy to change targetHost
    host_user = nixops.util.attr_property("container.targetUser", None)
    client_public_key = nixops.util.attr_property("container.clientPublicKey", None) # client is nixops
    client_private_key = nixops.util.attr_property("container.clientPrivateKey", None)
    public_host_key = nixops.util.attr_property("container.publicHostKey", None) # to maintain ~/.ssh/known_hosts
    pre_destroy_script = nixops.util.attr_property("container.preDestroy", None)

    def __init__(self, depl, name, id):
        MachineState.__init__(self, depl, name, id)
        self.ssh.register_flag_fun(self.get_ssh_flags)
        self.host_ssh = nixops.ssh_util.SSH(self.logger)
        self.host_ssh.register_host_fun(self.get_host_ssh)
        self.host_ssh.register_flag_fun(self.get_host_ssh_flags)

        if self._has_depl_uuid_collision():
            raise Exception("the deployement UUID cannot be used to deploy NixOps containers, please delete this and recreate again")

    def _has_depl_uuid_collision(self):
        """We require uniqueness of the 8-char prefix of the deployment UUID,
           due to the kernel's restriction of network device names length(15)
           and machinectl's length limit: HOST_NAME_MAX(64).
        """
        with self.depl._db:
            c = self.depl._db.cursor()
            c.execute("select count(*) from Deployments where substr(uuid, 1, 8) = ?;", (self.depl.uuid[0:8],))
            row = c.fetchone()
            return (row is not None and row[0] > 1)

    def _get_machinestate(self): # in case host is another deploying machine
        if not self.host.startswith("__machine-"): return None
        m = self.depl.get_machine(self.host[10:])
        if not m.started:
            raise Exception("host machine ‘{0}’ of container ‘{1}’ is not up".format(m.name, self.name))
        return m

    # * host ssh
    def get_host_ssh(self):
        m = self._get_machinestate()
        return self.host if m is None else m.get_ssh_name()

    def get_host_ssh_flags(self, *args, **kwargs):
        m = self._get_machinestate()
        if m is None:
            return super(NixOpsContainerState, self).get_ssh_flags(*args, **kwargs)
        else:
            return m.get_ssh_flags(*args, **kwargs)

    def _host_run_command(self, command, user=None, set_state=None, **kwargs):
        """
        Execute a command on the host machine via SSH. if you are not root user,
        '$sudo' is replaced by 'sudo', otherwise ''.

        For possible keyword arguments, please have a look at
        nixops.ssh_util.SSH.run_command().
        """
        ssh_user = user or self.host_user
        if ssh_user == "":
            ssh_user = os.environ['USER']
        if ssh_user != "root":
            cmd = "sudo='sudo'; set -e; sudo -v; " + command
        else:
            cmd = command
        if nixops.deployment.debug: self.log("run: " + cmd)
        prev_state = self.state
        try:
            if set_state is not None:
                self.state = set_state
            return self.host_ssh.run_command(cmd, user=ssh_user, **kwargs)
        except SSHConnectionFailed as e:
            self.state = self.UNREACHABLE if self.state == self.UP else prev_state
            raise

    # * container ssh
    def get_ssh_name(self):
        assert self.private_ipv4
        return self.private_ipv4
        #if self.host == "localhost":
        #    return self.private_ipv4
        #else:
        #    return self.get_host_ssh() + "~" + self.private_ipv4

    def get_ssh_private_key_file(self):
        return self._ssh_private_key_file or self.write_ssh_private_key(self.client_private_key)

    def get_ssh_flags(self, *args, **kwargs):
        # When using a remote container host, we have to proxy the ssh
        # connection to the container via the host.
        flags = super(NixOpsContainerState, self).get_ssh_flags(*args, **kwargs)
        flags += ["-i", self.get_ssh_private_key_file()]
        if self.host != "localhost":
            cmd = "ssh {0} {1}@{2} -W %h:%p".format(
                " ".join(self.get_host_ssh_flags()).replace("'", "\\'"),
                self.host_user,
                self.get_host_ssh())
            flags.extend(["-o", "ProxyCommand=" + cmd])
        return flags

    def wait_for_ssh(self, check=False):
        """Wait until the SSH port is open on this machine."""
        return True

    @property
    def resource_id(self):
        return self.vm_id

    def address_to(self, m):
        if isinstance(m, NixOpsContainerState) and self.host == m.host:
            return m.private_ipv4
        return MachineState.address_to(self, m)

    def get_physical_spec(self):
        """Set per-machine ssh public key."""
        # todo: cpus, memory, etc (like ansible's facts)
        # "lscpu -J | jq 'reduce .lscpu[] as $item ({}; . + {($item.field[:-1]): $item.data} )'"
        # "lsmem -Jb | jq '.memory | map(.size) | add/1024/1024'"
        return {
            ('users', 'extraUsers', 'root', 'openssh',
             'authorizedKeys', 'keys'): [ self.client_public_key ]
        }

    def _install_container(self, instance_id, path, daemon_reload=False, start=False, user_script=None):
        self._host_run_command(''.join([
            # FIXME: container autoStart: machine.target.wants
            # allows non-NixOS to be a NixOps container host
            "INSTANCE_ID='{0}' MUTABLE=$(grep -xq NAME=NixOS /etc/os-release && echo '-mutable'); ",
            "set -e; $sudo mkdir -p /etc/systemd/nspawn; ",
            user_script + "; " if user_script is not None else "",
            "$sudo ln -snf {1}/etc/systemd/nspawn/$INSTANCE_ID.nspawn /etc/systemd/nspawn/; ",
            "$sudo ln -snf {1}/systemd-nspawn@$INSTANCE_ID.service /etc/systemd$MUTABLE/system/; ",
            "$sudo systemctl daemon-reload; " if daemon_reload else "",
            "$sudo systemctl start systemd-nspawn@$INSTANCE_ID" if start else ""
        ]).format(instance_id, path))

    def create_after(self, resources, defn):
        host = defn.host if defn else self.host
        if host and host.startswith("__machine-"):
            return {self.depl.get_machine(host[10:])}
        else:
            return {}

    def create(self, defn, check, allow_reboot, allow_recreate):
        assert isinstance(defn, NixOpsContainerDefinition)
        self.set_common_state(defn)

        if not self.client_private_key:
            (self.client_private_key, self.client_public_key) = nixops.util.create_key_pair()

        # Update ssh user for later use (e.g. stop, destory)
        self.host_user = defn.host_user
        self.pre_destroy_script = defn.pre_destroy_script

        if self.vm_id is None:
            instance_id = "{0}.{1}.{2}".format(self.name, self.depl.name, self.depl.uuid[0:8])
            if len(instance_id) > 64:
                raise Exception("machine name too long, machine name + deployemnt name must be named within 54 bytes")

            self.log("building initial configuration...")

            cmd = [ "nix-build", "<nixops/nixops-container-init.nix>",
                    "--argstr", "name", self.name,
                    "--argstr", "deploymentName", self.depl.name,
                    "--argstr", "uuid", self.depl.uuid,
                    "--argstr", "clientPublicKey", self.client_public_key,
                    "--arg", "containerAttrs", py2nix(defn.config["container"])
                    ] + self.depl._nix_path_flags()

            if nixops.deployment.debug: self.log("run: '{0}'".format("' '".join(cmd)))
            path = subprocess.check_output(cmd).rstrip()

            self.log("creating NixOps container...")

            self.host = defn.host  # save targetHost
            self.copy_closure_to(path)

            self.state = self.STARTING
            self._install_container(instance_id, path, daemon_reload=True, start=True, user_script=defn.pre_deploy_script)
            self.state = self.UP
            self.vm_id = instance_id
        else:
            # starting an already UP container does not have any side-effect
            self.start(send_keys=False)

        if self.private_ipv4 is None:
            #self._host_run_command("$sudo machinectl -l | grep % | grep -Po '\d+\.\d+.\d+.\d+'".replace('%', self.vm_id), check=False)
            #self._host_run_command("$sudo systemd-run -tqM % /run/current-system/sw/bin/ip a".replace('%', self.vm_id), check=False)
            #hostlocal_ipv4 = self._host_run_command("$sudo machinectl shell -q % /run/current-system/sw/bin/ip -br addr show dev host0 | grep -Po '\d+\.\d+.\d+.\d+';".replace('%', self.vm_id), capture_stdout=True, check=False).rstrip()
            hostlocal_ipv4 = self._host_run_command("COLUMNS=500 $sudo machinectl list -l | grep % | grep -Po '\d+\.\d+.\d+.\d+';".replace('%', self.vm_id), capture_stdout=True, check=False).rstrip()
            if hostlocal_ipv4 == "":
                raise Exception("cannot get container private IP address")
            self.private_ipv4 = hostlocal_ipv4
            self.log("IP address is {0}".format(self.private_ipv4))

        if self.public_host_key is None:
            cmd = "cat /var/lib/machines/%/etc/ssh/ssh_host_{ed25519,rsa}_key.pub".replace("%", self.vm_id)
            res = self._host_run_command(cmd, capture_stdout=True, check=False).rstrip().split('\n')
            assert len(res) > 0
            self.public_host_key = res[0]
            nixops.known_hosts.add(self.get_ssh_name(), self.public_host_key)

    def destroy(self, wipe=False):
        if not self.vm_id:
            return True
        if not self.depl.logger.confirm("are you sure you want to destroy NixOps container ‘{0}’?".format(self.name)):
            return False

        self.log("destroying NixOps container...")

        commands = [
            "INSTANCE_ID='%' MUTABLE=$(grep -xq NAME=NixOS /etc/os-release && echo '-mutable');",
            "$sudo machinectl terminate $INSTANCE_ID || true;",
            self.pre_destroy_script if self.pre_destroy_script is not None else "",
            "$sudo rm -f /etc/systemd/nspawn/$INSTANCE_ID.nspawn /etc/systemd$MUTABLE/system/systemd-nspawn@$INSTANCE_ID.service;",
            "$sudo chattr -i /var/lib/machines/$INSTANCE_ID/var/empty;",
            # learned from sad history... https://github.com/NixOS/nixpkgs/commit/d394d095ab6dc32f1ee45c75e51b56ca9a443548
            "function safe_remove_trees() {",
            r"  $sudo find $@ -mindepth 1 -xdev \( -type d -exec mountpoint -q \{\} \; \) -exec umount -fR \{\} +;",
            r"  $sudo rm --one-file-system -rf $@;",
            r"  ! $sudo ls $@ 2>/dev/null || { $sudo umount -fR $@; $sudo rm --one-file-system -rf $@; };",
            "};",
            "safe_remove_trees /nix/var/nix/{profiles,gcroots}/per-container/$INSTANCE_ID /var/lib/machines/$INSTANCE_ID"
        ]
        self._host_run_command('\n'.join(commands).replace("%", self.vm_id))

        if self.private_ipv4 is not None:
            nixops.known_hosts.remove(self.get_ssh_name(), self.public_host_key)
        self.public_host_key = None

        return True

    def get_ssh_for_copy_closure(self):
        # NixOps containers share the Nix store of the host, so we
        # should copy closures to the host.
        return self.host_ssh

    def copy_closure_to(self, path):
        if self.host == "localhost": return
        MachineState.copy_closure_to(self, path)

    def switch_to_configuration(self, method, sync, command=None):
        """
        Execute the script to switch to new configuration.
        Additionally, update the container settings and the service file.
        """
        # FIXME: deployment.py:activate_configs(dry_activate=true) need to be fixed
        if method == "dry-activate" or method == "test":
            command = command or "{0}/bin/switch-to-configuration".format(m.new_toplevel)
        elif method == "switch" or method == "boot":
            # make it boot default
            self._install_container(self.vm_id, self.new_toplevel)
        else:
            self.warn("unknown switch_to_configuration method: " + method)
            return 1

        res = MachineState.switch_to_configuration(self, method, sync, command=command)

        nspawn_changed = False # TODO: _host_run_command('[ "$(readlink $old/etc/systemd/nspawn/*.nspawn) $(readlink $old/etc/systemd/system/systemd-nspawn@*.service)" = ...]')
        if nspawn_changed:
            self.log("nspawn container settings have changed.")
            res = 100 if res == 0 else res

        return res

    def _check_container_placed(self, fragment_path):
        nixops_cont_srv = r'(/nix/store/[\w]{32}-nixos-system-[-\w.]+)/systemd-nspawn@([-\w.]+).service'
        matched = re.match(nixops_cont_srv, fragment_path)
        cmd = "$sudo test -f /etc/systemd/nspawn/{0}.nspawn -a -d /var/lib/machines/{0}/etc; echo $?".format(self.vm_id)
        ls = self._host_run_command(cmd, capture_stdout=True, check=False).rstrip()
        # self.log("match: {0}, ls: {1}".format(matched, ls))
        if matched and ls == "0": return True
        elif not matched and ls != "0": return False
        else: return None

    def _ask_systemctl_state(self):
        # possible values:
        #  LoadState=stub,loaded,not-found,bad-setting,error,merged,masked
        #  ActiveState=active,reloading,inactive,failed,activating,deactivating,maintenance
        #  SubState=dead,condition,start-pre,start,start-post,running,exited,reload,stop,stop-watchdog,stop-sigterm,stop-sigkill,stop-post,final-sigterm,final-sigkill,failed,auto-restart,cleaning
        #  UnitFileState=enabled,disabled,'',static
        #  StatusText=Terminating..., StatusErrno=0, Result=exit-code, NRestarts=0, ...
        cmd = "$sudo systemctl show systemd-nspawn@{0}.service --value".format(self.vm_id)
        cmd += " -p LoadState,ActiveState,SubState,FragmentPath,LoadError"
        statuses = self._host_run_command(cmd, capture_stdout=True).rstrip().split('\n')
        active_state = statuses[1]
        if active_state == "failed": result = self.STOPPED
        elif active_state == "inactive":
            has_container = self._check_container_placed(statuses[3])
            if has_container is True: result = self.STOPPED
            elif has_container is False: result = self.MISSING
            else: reuslt = self.UNKNOWN
        elif active_state == "activating" or active_state == "reloading": result = self.STARTING
        elif active_state == "active": result = self.UP  # may be changed to UNREACHABLE later
        elif active_state == "deactivating": result = self.STOPPING
        else: result = self.UNKNOWN  # "maintenance"
        return statuses + [result]

    def _is_running(self):
        cmd = "$sudo machinectl show {0} -p State --value 2>&1".format(self.vm_id)
        state = self._host_run_command(cmd, capture_stdout=True, check=False).rstrip()
        return state == "running"

    def _wait_for_stop(self):
        while True:
            running = self._is_running()
            if not running:
                break
            time.sleep(1)
            self.log_continue(".")

    def stop(self):
        if not self.vm_id: return True

        terminate = False
        if self.state == self.STOPPING:
            terminate = self.depl.logger.confirm(
                "are you willing to forcibly terminate the container ‘{0}’?".format(self.name))

        if not terminate:
            self.log("stopping container...")
            # this fails when the container is banished, so check=False
            cmd = "$sudo machinectl poweroff {0}".format(self.vm_id)
            self._host_run_command(cmd, set_state=self.STOPPING, check=False)
        else:
            self.log("forcibly terminating container...")
            self._host_run_command("$sudo machinectl terminate {0}".format(self.vm_id))

        # https://github.com/NixOS/nixpkgs/pull/32992#discussion_r158586048
        self._wait_for_stop()
        self.check()

    def start(self, send_keys=True):
        if not self.vm_id: return True
        if self.state != self.UP: self.log("starting container...")
        try:
            cmd = "$sudo machinectl start {0}".format(self.vm_id)
            self._host_run_command(cmd, set_state=self.STARTING)
            self.state = self.UP
            if send_keys: self.send_keys()
        except SSHCommandFailed as e:
            self.check()
            raise

    def _check(self, res):
        if not self.vm_id:
            res.exists = False
            return
        try:
            statuses = self._ask_systemctl_state()
        except:
            raise
        self.state = statuses[5]
        if self.state not in [ self.MISSING, self.STOPPED, self.UP ]:
            res.messages = [ ','.join(statuses[:3] + [statuses[4]]) ]
        if self.state == self.UNKNOWN: return
        res.exists = self.state != self.MISSING
        res.is_up = self.state in [self.STARTING, self.UP, self.STOPPING]
        if self.state == self.UP:
            MachineState._check(self, res)
