import os
import pulumi
import pulumi_proxmoxve as proxmoxve
import pulumi_command as command

# === Config ===
cfg = pulumi.Config("pve")
node_name     = cfg.require("nodeName")
datastore_id  = cfg.require("datastoreId")
pool_id       = cfg.get("poolId")
template_vmid = cfg.require_int("templateVmid")

vm = pulumi.Config("vm")
vm_username   = vm.get("username") or "debian"
ssh_pub_key   = vm.require("sshPubKey")   # <-- clé publique injectée via cloud-init
vm_cores      = vm.get_int("cores") or 2
vm_mem_mb     = vm.get_int("memoryMb") or 2048
bridge        = vm.get("bridge") or "vmbr0"

# IP statique (défaut = 192.168.1.160/24 + GW 192.168.1.1)
vm_ip_cidr = vm.get("ipCidr") or "192.168.1.160/24"
vm_gateway = vm.get("gateway") or "192.168.1.1"
vm_ip_plain = vm.get("ip") or (vm_ip_cidr.split("/")[0] if "/" in vm_ip_cidr else vm_ip_cidr)

# Provider (tokens en variables d'env)
provider = proxmoxve.Provider(
    "proxmoxve",
    endpoint=os.environ.get("PROXMOX_VE_ENDPOINT"),
    api_token=os.environ.get("PROXMOX_VE_API_TOKEN"),
    insecure=(os.environ.get("PROXMOX_VE_INSECURE") == "true"),
    min_tls="1.3",
)

vm_name = f"ciweb-{pulumi.get_stack()}"

# Cloud-init IP config + DNS (ATTENTION: 'servers' doit être une LISTE)
ip_configs = [
    proxmoxve.vm.VirtualMachineInitializationIpConfigArgs(
        ipv4=proxmoxve.vm.VirtualMachineInitializationIpConfigIpv4Args(
            address=vm_ip_cidr,
            gateway=vm_gateway,
        )
    )
]

# === VM clone (pas de start auto provider) ===
vm_res = proxmoxve.vm.VirtualMachine(
    "testVm",
    node_name=node_name,
    name=vm_name,
    pool_id=pool_id,
    started=False,  # on démarre nous-mêmes via l'API (plus fiable depuis le runner)
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
        type="nocloud",
        datastore_id=datastore_id,
        dns=proxmoxve.vm.VirtualMachineInitializationDnsArgs(
            domain="example.com",
            servers=[vm_gateway],  # ex: ["192.168.1.1"] — LISTE, pas string
        ),
        ip_configs=ip_configs,
        user_account=proxmoxve.vm.VirtualMachineInitializationUserAccountArgs(
            username=vm_username,
            keys=[ssh_pub_key],
        ),
    ),
    opts=pulumi.ResourceOptions(provider=provider),
)

pulumi.export("vmId", vm_res.vm_id)
pulumi.export("vmName", vm_res.name)

# === Retire IDE3 éventuel (host_cdrom vide) avant start ===
fix_cd = command.local.Command(
    "fix-ide3-if-present",
    create=vm_res.vm_id.apply(lambda vid: f"""bash -ceu '
code=$(curl -sS -k -o /dev/null -w "%{{http_code}}\\n" \
  -H "Authorization: PVEAPIToken=$PVE_TOKEN" \
  -X PUT --data-urlencode "delete=ide3" \
  "$PVE_ENDPOINT/api2/json/nodes/{node_name}/qemu/{vid}/config"); \
[[ "$code" =~ ^(200|202)$ ]] || true
'"""),
    environment={
        "PVE_ENDPOINT": os.environ.get("PROXMOX_VE_ENDPOINT"),
        "PVE_TOKEN": os.environ.get("PROXMOX_VE_API_TOKEN"),
    },
    opts=pulumi.ResourceOptions(depends_on=[vm_res]),
)

# === Start via API PVE (robuste) ===
start_vm = command.local.Command(
    "force-start-vm",
    create=vm_res.vm_id.apply(lambda vid: f"""bash -ceu '
code=$(curl -sS -k -o /dev/null -w "%{{http_code}}\\n" \
  -H "Authorization: PVEAPIToken=$PVE_TOKEN" \
  -X POST "$PVE_ENDPOINT/api2/json/nodes/{node_name}/qemu/{vid}/status/start"); \
[[ "$code" =~ ^(200|202|204)$ ]] || (echo "Start failed, HTTP $code" >&2; exit 1)
'"""),
    environment={
        "PVE_ENDPOINT": os.environ.get("PROXMOX_VE_ENDPOINT"),
        "PVE_TOKEN": os.environ.get("PROXMOX_VE_API_TOKEN"),
    },
    opts=pulumi.ResourceOptions(depends_on=[fix_cd]),
)

# === IP effective: priorité à l'IP statique; sinon IP vue par l'agent si dispo ===
cfg_vm_ip = vm_ip_plain

candidates = []
for attr_name in ("ipv4_addresses", "guest_ipv4_addresses", "ip_addresses"):
    attr = getattr(vm_res, attr_name, None)
    if attr is not None:
        candidates.append(attr)

if candidates:
    ip_from_agent = pulumi.Output.all(*candidates).apply(
        lambda lists: next((lst[0] for lst in lists if lst), None)
    )
else:
    ip_from_agent = pulumi.Output.from_input(None)

vm_ip_output = pulumi.Output.all(pulumi.Output.from_input(cfg_vm_ip), ip_from_agent).apply(
    lambda t: t[0] or t[1]
)

# === Wait SSH (backoff exponentiel), clé privée via env VM_SSH_PRIVATE_KEY ===
private_key = os.environ.get("VM_SSH_PRIVATE_KEY")
if not private_key:
    raise pulumi.RunError("VM_SSH_PRIVATE_KEY doit être défini")

wait_script = pulumi.Output.all(vm_ip_output, pulumi.Output.from_input(private_key)).apply(
    lambda args: f"""#!/usr/bin/env bash
set -euo pipefail
IP="{args[0]}"
[ -n "$IP" ] || {{ echo "ERROR: IP non disponible"; exit 2; }}

key=/tmp/pulumi_tmp_key_$$
umask 077
cat > "$key" <<'KEY'
{args[1]}
KEY

sleep_s=2
for i in $(seq 1 12); do
  if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$key" {vm_username}@${{IP}} 'echo ok' >/dev/null 2>&1; then
    rm -f "$key"; exit 0
  fi
  sleep "$sleep_s"
  if [ "$sleep_s" -lt 30 ] ; then sleep_s=$(( sleep_s*2 )); else sleep_s=30; fi
done

echo "SSH non disponible après attente"
rm -f "$key"
exit 1
"""
)

wait_for_ssh = command.local.Command(
    "wait-for-ssh",
    create=wait_script,
    opts=pulumi.ResourceOptions(depends_on=[start_vm]),
)

# === Remote provisioning ===
conn = command.remote.ConnectionArgs(
    host=vm_ip_output,
    user=vm_username,
    private_key=private_key,
)

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

pulumi.export("vm_ip", vm_ip_output)
