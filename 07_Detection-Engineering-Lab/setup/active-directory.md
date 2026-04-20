# Active Directory Setup

## Domain Configuration

- **Domain:** lab.local
- **Forest/Domain Functional Level:** Windows Server 2016 (compatibility with older tooling)
- **NetBIOS Name:** LAB

AD DS, DNS, and DHCP roles installed on DC01. DHCP is configured but disabled in favor of static assignments for lab predictability.

## DC01 Promotion

After installing the AD DS role, DC01 was promoted to a domain controller with an integrated DNS zone for `lab.local`. A reverse lookup zone was created for `56.168.192.in-addr.arpa`.

Key decisions:
- **DSRM password** set and documented offline
- **Global Catalog** enabled on DC01 (single-DC environment)
- **DNS forwarders** left unconfigured — no external resolution needed in an isolated lab

## Organizational Unit Structure

```
lab.local
├── Lab Users
│   ├── svc-admin (domain admin — attack simulation)
│   └── jsmith (standard user — normal activity baseline)
├── Lab Computers
│   └── WS01
├── Lab Servers
│   └── DC01
└── Lab GPOs
```

Dedicated OUs allow scoped GPO application. Sysmon deployment GPO is linked to both `Lab Computers` and `Lab Servers`.

## User Accounts

| Account | Type | Purpose |
|---|---|---|
| Administrator | Built-in Domain Admin | DC management only |
| svc-admin | Domain Admin | Simulated compromised privileged account |
| jsmith | Domain User | Standard user for baseline activity |
| wazuh-svc | Domain User | Wazuh agent service account (limited permissions) |

`svc-admin` intentionally has Domain Admin rights to simulate a compromised service account — a realistic scenario in post-exploitation lateral movement.

## Domain Join — WS01

WS01 joined to `lab.local` using the `Administrator` account. DNS on WS01 points to DC01 (192.168.56.10) — required before domain join.

Post-join validation:

```powershell
# Confirm domain membership
(Get-WmiObject Win32_ComputerSystem).Domain

# Verify DC connectivity
nltest /dsgetdc:lab.local
```

## Group Policy

GPOs applied in this lab:

| GPO Name | Linked To | Purpose |
|---|---|---|
| Deploy-Sysmon | Lab Computers, Lab Servers | Installs and configures Sysmon via startup script |
| Enable-WinRM | Lab Computers | Enables WinRM for remote management during testing |
| Audit-Policy | Lab Computers, Lab Servers | Configures advanced audit policy for supplementary event generation |
