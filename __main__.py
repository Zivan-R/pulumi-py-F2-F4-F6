import os
import json
import ssl
import urllib.request
import pulumi
import pulumi_proxmoxve as proxmoxve
import pulumi_command as command

# === Config Proxmox / VM ===
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
bridge        = vm.get("bridge") or "vmbr0"

# IP statique par défaut (surcharge possible via vm:ipCidr / vm:gateway / vm:ip)
vm_ip_cidr  = vm.get("ipCidr") or "192.168.1.160/24"
vm_gateway  = vm.get("gateway") or "192.168.1.1"
vm_ip_plain = vm.get("ip") or (vm_ip_cidr.split("/")[0] if "/" in vm_ip_cidr else vm_ip_cidr)

# Provider PVE (env requis: PROXMOX_VE_ENDPOINT, PROXMOX_VE_API_TOKEN, PROXMOX_VE_INSECURE)
provider = proxmoxve.Provider(
    "proxmoxve",
    endpoint=os.environ.get("PROXMOX_VE_ENDPOINT"),
    api_token=os.environ.get("PROXMOX_VE_API_TOKEN"),
    insecure=(os.environ.get("PROXMOX_VE_INSECURE") == "true"),
    min_tls="1.3",
)

vm_name = f"ciweb-{pulumi.get_stack()}"

# === Détection idempotente VM existante ===
def _find_existing_vmid(endpoint: str, token: str, node: str, name: str):
    if not endpoint or not token:
        return None
    try:
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(
            f"{endpoint}/api2/json/nodes/{node}/qemu",
            headers={"Authorization": f"PVEAPIToken={token}"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
        for item in data.get("data", []):
            if str(item.get("name")) == name:
                return int(item.get("vmid"))
    except Exception:
        return None
    return None

_existing_vmid = _find_existing_vmid(
    os.environ.get("PROXMOX_VE_ENDPOINT"),
    os.environ.get("PROXMOX_VE_API_TOKEN"),
    node_name,
    vm_name,
)

# Cloud-init IP + DNS
ip_configs = [
    proxmoxve.vm.VirtualMachineInitializationIpConfigArgs(
        ipv4=proxmoxve.vm.VirtualMachineInitializationIpConfigIpv4Args(
            address=vm_ip_cidr,
            gateway=vm_gateway,
        )
    )
]

# === Crée la VM seulement si elle n'existe pas déjà ===
vm_res = None
if _existing_vmid is None:
    vm_res = proxmoxve.vm.VirtualMachine(
        "testVm",
        node_name=node_name,
        name=vm_name,
        pool_id=pool_id,
        started=False,
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
                servers=[vm_gateway],
            ),
            ip_configs=ip_configs,
            user_account=proxmoxve.vm.VirtualMachineInitializationUserAccountArgs(
                username=vm_username,
                keys=[ssh_pub_key],
            ),
        ),
        opts=pulumi.ResourceOptions(provider=provider),
    )
    vm_id_output = vm_res.vm_id
else:
    vm_id_output = pulumi.Output.from_input(_existing_vmid)

pulumi.export("vmId", vm_id_output)
pulumi.export("vmName", pulumi.Output.from_input(vm_name))
pulumi.export("vm_ip", pulumi.Output.from_input(vm_ip_plain))

# === Retire IDE3 éventuel ===
fix_cd_dep = [vm_res] if vm_res is not None else None
fix_cd = command.local.Command(
    "fix-ide3-if-present",
    create=vm_id_output.apply(lambda vid: f"""bash -ce '
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
    opts=pulumi.ResourceOptions(depends_on=fix_cd_dep),
)

# === Démarrage idempotent via API PVE ===
ensure_start = command.local.Command(
    "ensure-start",
    create=vm_id_output.apply(lambda vid: f"""bash -ce '
json=$(curl -sS -k -H "Authorization: PVEAPIToken=$PVE_TOKEN" \
  "$PVE_ENDPOINT/api2/json/nodes/{node_name}/qemu/{vid}/status/current" || true)
if echo "$json" | grep -q '"status":"stopped"'; then
  code=$(curl -sS -k -o /dev/null -w "%{{http_code}}\\n" \
    -H "Authorization: PVEAPIToken=$PVE_TOKEN" \
    -X POST "$PVE_ENDPOINT/api2/json/nodes/{node_name}/qemu/{vid}/status/start")
  [[ "$code" =~ ^(200|202|204)$ ]] || (echo "Start failed, HTTP $code" >&2; exit 1)
fi
'"""),
    environment={
        "PVE_ENDPOINT": os.environ.get("PROXMOX_VE_ENDPOINT"),
        "PVE_TOKEN": os.environ.get("PROXMOX_VE_API_TOKEN"),
    },
    opts=pulumi.ResourceOptions(depends_on=[fix_cd] if fix_cd_dep else None),
)

# === Attente SSH (bash, backoff exponentiel) ===
private_key = os.environ.get("VM_SSH_PRIVATE_KEY")
if not private_key:
    raise pulumi.RunError("VM_SSH_PRIVATE_KEY doit être défini")

wait_script = vm_id_output.apply(
    lambda _: f"""bash -ce '
IP="{vm_ip_plain}"
[ -n "$IP" ] || {{ echo "ERROR: IP non disponible"; exit 2; }}

key=$(mktemp)
umask 077
cat > "$key" <<'KEY'
{private_key}
KEY

sleep_s=2
for i in $(seq 1 12); do
  if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$key" {vm_username}@${{IP}} echo ok >/dev/null 2>&1; then
    rm -f "$key"; exit 0
  fi
  sleep "$sleep_s"
  if [ "$sleep_s" -lt 30 ]; then sleep_s=$(( sleep_s*2 )); else sleep_s=30; fi
done

echo "SSH non disponible après attente"
rm -f "$key"
exit 1
'"""
)

wait_for_ssh = command.local.Command(
    "wait-for-ssh",
    create=wait_script,
    opts=pulumi.ResourceOptions(depends_on=[ensure_start]),
)

# === Provisionnement distant idempotent ===
conn = command.remote.ConnectionArgs(
    host=vm_ip_plain,
    user=vm_username,
    private_key=private_key,
)

install = command.remote.Command(
    "install-podman",
    connection=conn,
    create=f"""bash --noprofile --norc -ce '
sudo apt-get update -y
sudo apt-get install -y podman podman-compose git curl
sudo loginctl enable-linger {vm_username}
mkdir -p /home/{vm_username}/app
sudo chown -R {vm_username}:{vm_username} /home/{vm_username}/app
'""",
    opts=pulumi.ResourceOptions(depends_on=[wait_for_ssh]),
)

cp = command.remote.CopyToRemote(
    "copy-app",
    connection=conn,
    source=pulumi.FileArchive("app"),
    remote_path=f"/home/{vm_username}",
    opts=pulumi.ResourceOptions(depends_on=[install]),
)

stage_app = command.remote.Command(
    "stage-app-layout",
    connection=conn,
    create=f"""bash --noprofile --norc -ce '
set -e
mkdir -p /home/{vm_username}/app
# cas 1: extraction au bon endroit
if [ -d /home/{vm_username}/app/compose ]; then
  exit 0
fi
# cas 2: extraction à la racine du $HOME
if [ -d /home/{vm_username}/compose ] || [ -d /home/{vm_username}/web ]; then
  shopt -s dotglob || true
  [ -d /home/{vm_username}/compose ] && mv /home/{vm_username}/compose /home/{vm_username}/app/ || true
  [ -d /home/{vm_username}/web ] && mv /home/{vm_username}/web /home/{vm_username}/app/ || true
fi
# cas 3: extraction dans app/app
if [ -d /home/{vm_username}/app/app ]; then
  shopt -s dotglob || true
  mv /home/{vm_username}/app/app/* /home/{vm_username}/app/
  rmdir /home/{vm_username}/app/app || true
fi
sudo chown -R {vm_username}:{vm_username} /home/{vm_username}/app
ls -la /home/{vm_username}/app
'""",
    opts=pulumi.ResourceOptions(depends_on=[cp]),
)

up = command.remote.Command(
    "compose-up",
    connection=conn,
    create=f"""bash --noprofile --norc -ce '
cd /home/{vm_username}/app/compose
podman compose -f compose.yml up -d --build --scale web=2
podman ps
'""",
    opts=pulumi.ResourceOptions(depends_on=[stage_app]),
)

test = command.remote.Command(
    "smoke-test",
    connection=conn,
    create="""bash --noprofile --norc -ce '
curl -fsS --max-time 10 http://127.0.0.1:8080/health >/dev/null
'""",
    opts=pulumi.ResourceOptions(depends_on=[up]),
)
