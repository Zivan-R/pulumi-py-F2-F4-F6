import os
import pulumi
import pulumi_proxmoxve as proxmoxve
import pulumi_command as command

cfg = pulumi.Config("pve")
node_name     = cfg.require("nodeName")
datastore_id  = cfg.require("datastoreId")
pool_id       = cfg.get("poolId")
template_vmid = cfg.require_int("templateVmid")

vm = pulumi.Config("vm")
vm_username   = vm.get("username") or "debian"
ssh_pub_key   = vm.require("sshPubKey")
vm_cores      = vm.get_int("cores") or 2
vm_mem_mb     = vm.get_int("memoryMb") or 2048
bridge        = "vmbr0"

provider = proxmoxve.Provider(
    "proxmoxve",
    endpoint=os.environ.get("PROXMOX_VE_ENDPOINT"),
    api_token=os.environ.get("PROXMOX_VE_API_TOKEN"),
    insecure=(os.environ.get("PROXMOX_VE_INSECURE") == "true"),
    min_tls="1.3",
)

vm_name = f"ciweb-{pulumi.get_stack()}"

# 1) Créer la VM clonée
vm_res = proxmoxve.vm.VirtualMachine(
    "testVm",
    node_name=node_name,
    name=vm_name,
    pool_id=pool_id,
    started=False,
    #on_boot=True,
    agent=proxmoxve.vm.VirtualMachineAgentArgs(enabled=True, trim=True),
    cpu=proxmoxve.vm.VirtualMachineCpuArgs(cores=vm_cores, sockets=1, type="host"),
    memory=proxmoxve.vm.VirtualMachineMemoryArgs(dedicated=vm_mem_mb),
    network_devices=[proxmoxve.vm.VirtualMachineNetworkDeviceArgs(model="virtio", bridge=bridge)],
    clone=proxmoxve.vm.VirtualMachineCloneArgs(
        vm_id=template_vmid,
        datastore_id=datastore_id,
        full=True,
        retries=3,
    ),
    initialization=proxmoxve.vm.VirtualMachineInitializationArgs(
        user_account=proxmoxve.vm.VirtualMachineInitializationUserAccountArgs(
            username=vm_username,
            keys=[ssh_pub_key],
        ),
    ),
    opts=pulumi.ResourceOptions(provider=provider),
)

# Pour une raison inconnue, la vm créée crée un emplacement cd vide ide3 qui n'existe pas sur le template: fix rapide
fix_cd = command.local.Command(
    "fix-ide3-if-present",
    create=vm_res.vm_id.apply(lambda vid: f"""bash -ceu '
# retire IDE3 si présent : PUT /nodes/<node>/qemu/<vmid>/config with delete=ide3
code=$(curl -sS -k -o /dev/null -w "%{{http_code}}\\n" \
  -H "Authorization: PVEAPIToken=$PVE_TOKEN" \
  -X PUT --data-urlencode "delete=ide3" \
  "$PVE_ENDPOINT/api2/json/nodes/{node_name}/qemu/{vid}/config"); \
[[ "$code" =~ ^(200|202)$ ]] || echo "delete ide3 skipped/failed (HTTP $code)"; true
'"""),
    environment={
        "PVE_ENDPOINT": os.environ.get("PROXMOX_VE_ENDPOINT"),
        "PVE_TOKEN": os.environ.get("PROXMOX_VE_API_TOKEN"),
    },
    opts=pulumi.ResourceOptions(depends_on=[vm_res]),
)

start_vm = command.local.Command(
    "force-start-vm",
    create=vm_res.vm_id.apply(lambda vid: f"""bash -ceu '
curl -sS -k -o /dev/null -w "%{{http_code}}\\n" \
  -H "Authorization: PVEAPIToken=$PVE_TOKEN" \
  -X POST "$PVE_ENDPOINT/api2/json/nodes/{node_name}/qemu/{vid}/status/start" | grep -qE "^(200|202|204)$"
'"""),
    environment={
        "PVE_ENDPOINT": os.environ.get("PROXMOX_VE_ENDPOINT"),
        "PVE_TOKEN": os.environ.get("PROXMOX_VE_API_TOKEN"),
    },
    opts=pulumi.ResourceOptions(depends_on=[vm_res]),
)

pulumi.export("vmId", vm_res.vm_id)
pulumi.export("vmName", vm_res.name)

# 2) Provision dans la VM via SSH : Podman + app + HAProxy ---
cfg_vm_ip = vm.get("ip")  # override manuel possible

private_key = os.environ.get("VM_SSH_PRIVATE_KEY")
if not private_key:
    raise pulumi.RunError("VM_SSH_PRIVATE_KEY doit être défini")

# tenter plusieurs attributs possibles exposés par le provider Proxmox (compatibilité)
candidates = []
for attr_name in ("ipv4_addresses", "guest_ipv4_addresses", "ip_addresses"):
    attr = getattr(vm_res, attr_name, None)
    if attr is not None:
        candidates.append(attr)

if candidates:
    # combine les candidats et renvoie la première IP trouvée (premier élément de la première liste non vide)
    ip_from_agent = pulumi.Output.all(*candidates).apply(
        lambda lists: next((lst[0] for lst in lists if lst), None)
    )
else:
    ip_from_agent = pulumi.Output.from_input(None)

# vm_ip_final : priorise cfg_vm_ip si présent, sinon prend ip_from_agent
vm_ip_output = pulumi.Output.all(pulumi.Output.from_input(cfg_vm_ip), ip_from_agent).apply(
    lambda t: t[0] or t[1]
)

# wait-for-ssh local : boucle depuis la machine qui exécute Pulumi (jumphost/CI) jusqu'à ce que SSH réponde
# On injecte la private key temporairement dans un fichier, on tente des connexions SSH répétées, puis on supprime le fichier.
wait_script = pulumi.Output.all(vm_ip_output, pulumi.Output.from_input(private_key)).apply(
    lambda args: f"""#!/usr/bin/env bash
set -eux
IP="{args[0]}"
if [ -z "$IP" ]; then
  echo "ERROR: IP non disponible pour la VM (ni vm:ip ni agent)."; exit 2
fi

cat > /tmp/pulumi_tmp_key <<'KEY'
{args[1]}
KEY
chmod 600 /tmp/pulumi_tmp_key

# Attente SSH : 60 essais * 2s = ~120s max (ajuste si besoin)
for i in $(seq 1 60); do
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i /tmp/pulumi_tmp_key {vm_username}@${{IP}} 'echo ok' && exit 0
  echo "SSH not ready (attempt $i)..."
  sleep 2
done

echo "SSH non disponible après les tentatives"; rm -f /tmp/pulumi_tmp_key; exit 1
"""
)

wait_for_ssh = command.local.Command(
    "wait-for-ssh",
    create=wait_script,
    opts=pulumi.ResourceOptions(depends_on=[start_vm]),
)

# ConnectionArgs utilise vm_ip_output (Output), Pulumi attendra la résolution
conn = command.remote.ConnectionArgs(
    host=vm_ip_output,
    user=vm_username,
    private_key=private_key,
)

# Commandes distantes, s'exécutent après que SSH soit joignable
install = command.remote.Command(
    "install-podman",
    connection=conn,
    create=f"""set -eux
sudo apt-get update -y
sudo apt-get install -y podman podman-compose git curl
sudo loginctl enable-linger {vm_username}
mkdir -p /home/{vm_username}/app && sudo chown -R {vm_username}:{vm_username} /home/{vm_username}/app
""",
    opts=pulumi.ResourceOptions(depends_on=[wait_for_ssh]),
)

cp = command.remote.CopyToRemote(
    "copy-app",
    connection=conn,
    source=pulumi.FileArchive("app"),
    remote_path=f"/home/{vm_username}/app",
    opts=pulumi.ResourceOptions(depends_on=[install]),
)

up = command.remote.Command(
    "compose-up",
    connection=conn,
    create=f"""set -eux
cd /home/{vm_username}/app/compose
podman compose -f compose.yml up -d --build --scale web=2
podman ps
""",
    opts=pulumi.ResourceOptions(depends_on=[cp]),
)

test = command.remote.Command(
    "smoke-test",
    connection=conn,
    create="""set -eux
curl -fsS --max-time 10 http://127.0.0.1:8080/health >/dev/null
""",
    opts=pulumi.ResourceOptions(depends_on=[up]),
)

# 8) expose l'IP finale
pulumi.export("vm_ip", vm_ip_output)
