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

### Host virtual networks

| Adapter | Type | Subnet |
|---|---|---|
| `vmnet1` | Host-only | 172.16.204.0/24 |
| `vmnet8` | NAT | 192.168.234.0/24 |

### ⚠️ Current state — needs changing

**Both VMs ship on NAT (`vmnet8`) and have working internet egress through the host.**
The REMnux OVF defaults to NAT, and FlareVM was left on it.

A Windows 11 detonation box with NAT egress will let anything you run reach the
internet. That means second-stage payload retrieval, C2 check-in, and your home IP
appearing in the operator's logs.

### Target state

Move both guests off NAT before any sample is introduced:

```bash
# in each .vmx, replace:
#   ethernet0.connectionType = "nat"
# with:
#   ethernet0.connectionType = "custom"
#   ethernet0.vnet = "/dev/vmnet2"
```

Edit while the VM is powered off, or use **VM → Settings → Network Adapter → Custom**.

Preferred design is a fully isolated segment (`vmnet2`, created with no host virtual
adapter and no DHCP) with REMnux dual-homed as the only gateway:

```
FlareVM ── vmnet2 (isolated) ── REMnux ── (optionally) vmnet1
                                   │
                              INetSim + tcpdump
```

REMnux runs INetSim to fake DNS/HTTP/HTTPS/SMTP/IRC so the sample believes it has
connectivity, while full PCAP is captured. Nothing reaches the real network.

Verify isolation from the Windows guest before trusting it — confirm it cannot reach
the LAN gateway or any public address.

---

## Operating rules

**Snapshots.** Snapshot clean before every run, revert after every run. Never analyze
on top of a dirty VM. FlareVM has `Snapshot1` as its baseline.

**No host integration.** Disable shared folders, clipboard sharing, and drag-and-drop
on the analysis guests. They are both a VM-detection artifact and an escape surface.
Workstation enables copy/paste and drag-drop by default — turn them off explicitly in
the `.vmx`:

```
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"
isolation.tools.dnd.disable = "TRUE"
isolation.tools.hgfs.disable = "TRUE"
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
