# Malware Analysis Lab

Linux host, Windows + REMnux guests, VMware Workstation.

Last verified: 2026-09-30

---

## Topology

```
Fedora 44 host (bare metal)
├── FlareVM   — Windows 11 x64, 8 vCPU, 16 GB   ← detonation / victim
└── REMnux    — Ubuntu Noble x64, 2 vCPU, 4 GB  ← gateway, capture, static analysis
```

### Why a Linux host

The host is not a valid target for the samples being analyzed. Nearly everything
examined here is Windows PE. A hypervisor escape, a forgotten shared folder, or a
mis-click on a `.exe` in the host file manager has no native execution path on Linux.

The realistic risk is not an escape CVE — it is human error. A Linux host turns most
of those mistakes into nothing.

Secondary benefits: host AV does not quarantine samples mid-transfer; the tooling
(INetSim, Suricata, Zeek, CAPEv2, mitmproxy) is Linux-host-first.

**Do not install Wine on this host.** It registers binfmt handlers that make `.exe`
files directly executable on Linux, which gives back the exact property this design
is built around.

---

## Host environment

| | |
|---|---|
| OS | Fedora 44 |
| Kernel | 7.2.5-200.fc44.x86_64 |
| Hypervisor | VMware Workstation 26.0.1 (build 25688693) |
| Secure Boot | Disabled |
| Kernel modules | `vmmon`, `vmnet` loaded |
| Lab root | `~/vmware/` |

Secure Boot is disabled because `vmmon` / `vmnet` are unsigned out-of-tree modules.
If Secure Boot is ever re-enabled, they must be MOK-signed or the hypervisor will not
start.

---

## Fedora 44 setup: missing legacy libraries

**This is the one that costs hours if you don't know it.**

VMware Workstation installs from a `.bundle`, not an RPM, so `dnf` never learns its
dependencies. Workstation 26 is linked against two legacy libraries that Fedora 44
has retired from the default install:

| Library | Fedora package | Note |
|---|---|---|
| `libnsl.so.1` | `libnsl` | Legacy NIS. Default `libnsl2` provides `.so.2`, not `.so.1` |
| `libcrypt.so.1` | `libxcrypt-compat` | Pre-libxcrypt crypt ABI. Default provides `.so.2` |

```bash
sudo dnf install libnsl libxcrypt-compat
```

### Why this breaks OVA import specifically

Workstation's GUI **File → Open** on an `.ova` shells out to `ovftool` to do the
conversion. When `ovftool` cannot load its libraries it dies immediately, and the
GUI surfaces a generic, useless import failure. The real error only appears on the
CLI:

```
ovftool.bin: error while loading shared libraries: libnsl.so.1: cannot open shared object file
```

Verify the fix:

```bash
ovftool --version
```

### Diagnosing further missing libraries

`ldd` run directly on the binary is misleading — it reports `libxerces-c`,
`libvmacore`, `libvmomi` and `libvim-types` as missing. Those are **red herrings**.
VMware bundles them in `/usr/lib/vmware-ovftool/` and the `/usr/bin/ovftool` wrapper
script resolves them via `LD_LIBRARY_PATH`.

To see only the genuinely missing *system* libraries, put the bundle on the path first:

```bash
LD_LIBRARY_PATH=/usr/lib/vmware-ovftool ldd /usr/lib/vmware-ovftool/ovftool.bin | grep 'not found'
```

Then identify the provider:

```bash
dnf provides 'libcrypt.so.1()(64bit)'
```

---

## Importing the REMnux OVA

Source: <https://remnux.org> — distributed as `remnux-noble-amd64.ova` (~8.9 GB).

### Verify before importing

The OVA is a plain tar. Confirm structure and checksums against the bundled manifest:

```bash
tar tvf remnux-noble-amd64.ova
tar xf remnux-noble-amd64.ova remnux-noble-amd64.ovf remnux-noble-amd64.mf
cat remnux-noble-amd64.mf
sha256sum remnux-noble-amd64.ovf
```

A truncated download is a common cause of import failures that look like corruption
errors. The manifest contains SHA256 for both the `.ovf` and the compressed `.vmdk`.

### Import

CLI is preferable to the GUI — real error messages and a progress bar:

```bash
mkdir -p ~/vmware/REMnux
ovftool --lax --allowExtraConfig ~/Downloads/remnux-noble-amd64.ova ~/vmware/REMnux/REMnux.vmx
```

`--lax` relaxes OVF conformance checks. In the GUI equivalent, clicking **Retry** on
the "did not pass OVF specification conformance" dialog does the same thing — it is
not an error, and Retry generally succeeds.

### Shipped specs

vmx-14 · `ubuntu64Guest` · 2 vCPU · 4 GB RAM · 100 GB thin-provisioned SATA ·
E1000 NIC · ~20 GB populated after import.

---

## Network isolation

**Status: built 2026-09-30.** Host segment created, both guests moved off NAT.
Guest-side addressing and INetSim still to do — see "Remaining guest setup" below.

### Design

```
        ┌─────────────────────────────────────────┐
        │  vmnet2 — 10.0.66.0/24                  │
        │  no host adapter · no DHCP · no NAT     │
        │                                         │
        │   FlareVM ──────────── REMnux           │
        │   10.0.66.10          10.0.66.2         │
        │   gw/DNS 10.0.66.2    INetSim + tcpdump │
        └─────────────────────────────────────────┘
                                   │
                          eth1 (NAT) — DISCONNECTED
                          maintenance only
```

`vmnet2` is a pure isolated switch. Because `VNET_2_VIRTUAL_ADAPTER` is `no`, the
Fedora host has **no interface on it at all** — the host cannot reach the guests and
the guests cannot reach the host. No DHCP server runs on it, so there is also no
VMware `dhcpd` on the segment to fingerprint or leak host information.

### Host configuration

Appended to `/etc/vmware/networking` (original backed up alongside it):

```
answer VNET_2_HOSTONLY_NETMASK 255.255.255.0
answer VNET_2_HOSTONLY_SUBNET  10.0.66.0
answer VNET_2_VIRTUAL_ADAPTER  no
answer VNET_2_DHCP             no
```

Applied with:

```bash
sudo vmware-networks --stop && sudo vmware-networks --start
```

Subnet chosen to avoid collision with the host LAN (`192.168.1.0/24`), `vmnet1`
(`172.16.204.0/24`) and `vmnet8` (`192.168.234.0/24`).

### Guest NIC configuration

| | FlareVM | REMnux |
|---|---|---|
| `ethernet0.connectionType` | `custom` | `custom` |
| `ethernet0.vnet` | `/dev/vmnet2` | `/dev/vmnet2` |
| `ethernet0.startConnected` | `TRUE` | `TRUE` |
| `ethernet1` | — | NAT, `startConnected = FALSE` |

REMnux's second NIC exists so the box can be updated without rebuilding the lab.
It is **disconnected at power-on** and must be attached by hand. Detach it again
before any sample is introduced.

### Remaining guest setup

Nothing below has been done yet — it has to happen inside the running VMs.

**REMnux** — static address on the isolated segment:

```bash
sudo nmcli con add type ethernet ifname ens33 con-name lab \
  ipv4.method manual ipv4.addresses 10.0.66.2/24
sudo nmcli con up lab
```

No gateway is set, deliberately. Confirm the interface name with `ip -br link` first.

Keep IP forwarding **off** so traffic cannot route out even if `eth1` is attached:

```bash
sudo sysctl -w net.ipv4.ip_forward=0
```

**INetSim** — fake DNS/HTTP/HTTPS/SMTP/IRC so samples believe they have connectivity.
In `/etc/inetsim/inetsim.conf`:

```
service_bind_address  10.0.66.2
dns_default_ip        10.0.66.2
```

Start it with `sudo systemctl start inetsim`. Capture alongside it:

```bash
sudo tcpdump -i ens33 -w /cases/$(date +%F-%H%M).pcap
```

**FlareVM** — static address pointing at REMnux for both gateway and DNS:

```
IP       10.0.66.10
Netmask  255.255.255.0
Gateway  10.0.66.2
DNS      10.0.66.2
```

### Verify isolation before trusting it

From FlareVM, all three must fail:

```
ping 192.168.1.1        # host LAN gateway
ping 8.8.8.8            # public internet
ping 192.168.234.1      # vmnet8 NAT gateway
```

And this must succeed:

```
ping 10.0.66.2          # REMnux
```

Re-run this check after any Workstation upgrade — upgrades have been known to reset
network settings.

## Operating rules

**Snapshots.** Snapshot clean before every run, revert after every run. Never analyze
on top of a dirty VM. FlareVM has `Snapshot1` as its baseline.

**No host integration.** Shared folders, clipboard sharing and drag-and-drop are
disabled on the analysis guests. They are both a VM-detection artifact and an escape
surface. Workstation enables copy/paste and drag-drop by default, so these are set
explicitly in the `.vmx` — **applied 2026-09-30**:

FlareVM (detonation box — everything off):

```
isolation.tools.copy.disable  = "TRUE"
isolation.tools.paste.disable = "TRUE"
isolation.tools.dnd.disable   = "TRUE"
isolation.tools.hgfs.disable  = "TRUE"
sharedFolder.maxNum           = "0"
```

REMnux (analysis box — shared folders off, clipboard left on so hashes and strings
can be copied out):

```
isolation.tools.hgfs.disable = "TRUE"
sharedFolder.maxNum          = "0"
```

**Sample transfer.** Move samples in over a read-only ISO built on the host, or pull
them over HTTP from REMnux. Never over a shared folder.

**Sample storage.** Always in password-protected zips using the convention password
`infected`. This prevents accidental host-side execution and stops scanners from
eating the archive.

**Anti-VM.** Malware fingerprints VMware aggressively. Expect samples to check for
`vmtoolsd`, VMware MAC OUIs (`00:0c:29`, `00:50:56`), SMBIOS vendor strings, and
VMware-specific devices. FlareVM's current generated MAC `00:0c:29:42:64:89` is a
textbook VMware OUI and is trivially detected.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| OVA import fails in GUI with no useful error | `ovftool` missing `libnsl.so.1` / `libcrypt.so.1` | `sudo dnf install libnsl libxcrypt-compat` |
| "did not pass OVF specification conformance" | Strict OVF validation | Click **Retry**, or use `ovftool --lax` |
| `ldd` shows VMware libs missing | Bundle not on library path | Not a real problem — see diagnosing section above |
| Workstation won't start after kernel update | `vmmon`/`vmnet` not rebuilt | Rebuild modules; check `lsmod \| grep vm` |
| Modules build but won't load | Secure Boot enabled, modules unsigned | MOK-sign them, or disable Secure Boot |
| Import fails partway through | Truncated download | Check disk `.vmdk.gz` SHA256 against the `.mf` |

### Health check

```bash
uname -r
mokutil --sb-state
lsmod | grep -E 'vmmon|vmnet'
vmware --version
ovftool --version
ip -br addr show | grep vmnet
```

---

## References

- REMnux — <https://remnux.org>
- FLARE-VM — <https://github.com/mandiant/flare-vm>
- INetSim — <https://www.inetsim.org>
