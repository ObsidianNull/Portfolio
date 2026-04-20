# VMware Network Configuration

## Network Design

Host-only adapter configured in VMware Workstation to create an isolated 192.168.56.0/24 segment. No NAT or bridged networking — all traffic stays local to the hypervisor.

## VMware Virtual Network Editor

- **Adapter:** VMnet1 (Host-only)
- **Subnet:** 192.168.56.0
- **Mask:** 255.255.255.0
- **DHCP:** Disabled (all systems use static IPs)

Disabling VMware's built-in DHCP avoids IP conflicts and ensures each VM has a predictable, documented address.

## Static IP Assignments

| VM | IP Address | Gateway | DNS |
|---|---|---|---|
| DC01 | 192.168.56.10 | 192.168.56.1 | 127.0.0.1 |
| WS01 | 192.168.56.20 | 192.168.56.1 | 192.168.56.10 |
| WAZUH-SVR | 192.168.56.40 | 192.168.56.1 | 192.168.56.10 |

DC01 uses localhost for DNS since it runs the AD-integrated DNS service. All other systems point to DC01 for DNS.

## VM Hardware Settings

Each VM is configured with a single NIC attached to the VMnet1 host-only network:

- **DC01:** 2 vCPUs, 4 GB RAM, 60 GB disk
- **WS01:** 2 vCPUs, 4 GB RAM, 50 GB disk
- **WAZUH-SVR:** 4 vCPUs, 8 GB RAM, 80 GB disk

Wazuh Manager requires additional resources for the indexer (OpenSearch) and dashboard components. Under-provisioning causes indexer crashes during high-ingest periods.

## Connectivity Validation

After configuring all three VMs, verify reachability:

```
# From WS01
ping 192.168.56.10    # DC01
ping 192.168.56.40   # WAZUH-SVR

# From WAZUH-SVR
ping 192.168.56.10    # DC01
ping 192.168.56.20    # WS01
```

Confirm DNS resolution from WS01:

```
nslookup dc01.lab.local 192.168.56.10
```
