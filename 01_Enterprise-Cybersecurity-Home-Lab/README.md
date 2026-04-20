# Enterprise Cybersecurity Home Lab

## Overview

## Target Architecture

Consists of:
- 1 x Domain Controller
- 1-2x Windows Clients
- 1 x Linux Machine
- 1 x SIEM Server (Splunk)
- 1 x Firewall/Router (pfSense)

[Attacker Kali Linux]
        |
   [pfSense Firewall]
        |
 -------------------------
 |          |            |
DC       Win10       Linux
 |
[Splunk SIEM]

## Methodology

### Phase 1: Set up Virtualization

1.  Install Hypervisor
    - Installed VMware Workstation as primary hypervisor

2. Configure Networking
    - Create an Internal Network (for lab traffic)

        Visiting the Virtual Network Editor option in VMWare, I created a new Host-Only network in order to connect the related VMs internally in a private network, setting the subnet IP to a valid private IP address space and the subnet mask to a valid address. I also choose to deselect the DHCP service so that it would be easy to assign static IPs to any VMs. 

    - NAT Network (for internet access if needed)

        Similar to creating an Internal Network, I also created a NAT network in the event that I want to use my VMs to have internet access later on.

### Phase 2: Build the Domain

3. Install Windows Server
    - I was able to download, install, and setup a VM with Windows Server 2022 directly from the Microsoft software center. Once the VM was setup, I went into it's settings and set a static IP using the previously made Internal Network. 

4. Promote to Domain Controller