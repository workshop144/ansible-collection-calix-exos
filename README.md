# workshop144.calix_exos

Unofficial Ansible modules for Calix EXOS routers (the GigaSpire family), using the router's own
local web interface.

**This project is not affiliated with, endorsed by or supported by Calix.** There is no published
API for the local interface. What is here was worked out by watching what the router's own admin
page sends, on equipment the authors administer. It is tested on the GS4227 and GS4227W running
EXOS 25.4.0 and may stop working after a firmware update. Use it only on equipment you are
allowed to administer. Many of these routers are owned and managed by an internet provider, which
can overwrite local changes at any time.

## What it does

Every module supports check mode and diff, reads the setting back after changing it, and fails
rather than guesses when the router's reply is not what it expects. A playbook run with
`--check --diff` therefore reports drift without changing the router. Passwords and Wi-Fi keys
are never returned.

Each module below was run against real routers of both models: it changed the setting, checked
it, and put it back. The playbooks that did so are in `tests/live/`.

| Module | Purpose |
|---|---|
| `info` | Read everything below, plus system, clients, Ethernet ports, WAN and internet status. Changes nothing. |
| `dhcp` | DHCP server: on or off, pool, lease time, DNS servers, host and domain name; the LAN address with `force`. |
| `dhcp_reservation` | One fixed address for a device. |
| `dns_host_mapping` | One local DNS name. |
| `ipv6_lan` | Router advertisement, DHCPv6 and IPv6 DNS servers on the LAN. |
| `wifi_network` | The primary Wi-Fi network: name, security, key, hidden. |
| `wifi_secondary_network` | Guest and other secondary Wi-Fi networks. |
| `wifi_radio` | A radio: on or off, DFS, MU-MIMO, 802.11ax/be, wide channels. |
| `upnp` | UPnP and UPnP NAT traversal. |
| `firewall` | Firewall level and stealth mode. |
| `firewall_rule` | One custom firewall rule (the Advanced Firewall page). |
| `dmz` | The DMZ host. |
| `port_forward` | One port forwarding rule. |
| `arp_spoofing` | ARP spoofing protection. |
| `access_schedule` | Cut a device off from the internet at set times. |
| `service_blocking_rule`, `service_blocking` | Named sets of ports, and blocking one for a device. |
| `controls` | Front LED and SIP ALG. |
| `device` | The name and kind of a device in the router's list. |
| `ping`, `traceroute` | Run the router's own ping and traceroute. |
| `backup` | Download the configuration backup to a file. |
| `reboot` | Restart the router and wait for it. |

### What was not exercised on a real router

The live runs changed one representative thing per module. These paths are covered by unit
tests only:

- `wifi_network`: only its hidden flag was changed live. Changing the name, security or key goes
  through the same request, but it disconnects every device, so it was not run against a
  network in use. The key encryption it uses was proven live by `wifi_secondary_network`.
- `wifi_secondary_network`: a guest network was created, re-keyed, moved between WPA2/WPA3 and
  WPA2, had its isolation turned off, and was removed. Work-from-home and custom networks, open
  and enhanced-open security, and 6 GHz were not run.
- `dhcp`: only the lease time was changed live. Turning DHCP off, changing the pool or the DNS
  servers, and changing `lan_address` or `lan_netmask` (which moves the router) were not run.
- `wifi_radio`: only MU-MIMO on the 6 GHz radio was changed live.
- `firewall_rule`: only the `ipv4_out` chain was used.
- `dmz`: set and cleared; replacing one host with another was not run.
- `port_forward`: TCP only, any source address.
- `info`: the `ddns` part was read only with dynamic DNS off.

### What is not covered, on purpose

- Changing the admin password, restoring a backup, factory reset, firmware upload and the setup
  wizard. A mistake in any of them can leave a router unreachable, and none can be tested and
  undone.
- Dynamic DNS and website blocking writes, and the time zone. They could not be tested: dynamic
  DNS needs an account with a provider, the routers refuse website blocking while the provider's
  security app runs, and the admin page has no time zone setting outside the setup wizard.
- Anything only the provider's support login can reach (WAN and VLAN setup, TR-069, voice).
- Wi-Fi channel, channel width and power: the admin page does not offer them.
- Smaller things on pages that are otherwise covered: a schedule or traffic priority for a
  secondary network, the TFTP options of the DHCP page, the Public LAN page, and starting a WPS
  pairing.

## Install

In `requirements.yml`:

```yaml
collections:
  - name: https://github.com/workshop144/ansible-collection-calix-exos.git
    type: git
    version: v0.2.0
```

then `ansible-galaxy collection install -r requirements.yml`. Needs ansible-core 2.17 or later
and nothing else.

## Connecting

The modules run on the control node and talk HTTPS to the router, so use `connection: local`
(or `delegate_to: localhost`). There is no SSH on these routers.

| Option | Default | Notes |
|---|---|---|
| `host` | required | Name or address of the router. |
| `username` | `admin` | |
| `password` | required | Never logged. Falls back to the environment variable `CALIX_EXOS_PASSWORD`. |
| `validate_certs` | `false` | The router ships with a self-signed certificate. |
| `timeout` | `30` | Seconds per request. The router can pause for around 15 seconds while it applies a change. |

Each task logs in, does its work and logs out (`reboot` ends its first session by restarting
the router). A failed login is never retried, because the router locks the account after
repeated failures.

Some changes disturb the network while the router applies them. Wi-Fi changes restart the
radios, so devices can drop for some seconds; a DHCP change restarts the DHCP and DNS service;
`reboot` takes everything offline for a few minutes. Each module's documentation says what to
expect (`ansible-doc workshop144.calix_exos.<module>`).

## Examples

```yaml
- name: Read the router
  workshop144.calix_exos.info:
    host: 192.0.2.1
    password: "{{ router_password }}"
  register: router

- name: UPnP must be off
  ansible.builtin.assert:
    that: not router.exos.security.upnp

- name: Reserve an address for the printer
  workshop144.calix_exos.dhcp_reservation:
    host: 192.0.2.1
    password: "{{ router_password }}"
    mac: "02:00:00:00:00:aa"
    ip: 192.0.2.150

- name: UPnP stays off
  workshop144.calix_exos.upnp:
    host: 192.0.2.1
    password: "{{ router_password }}"
    enabled: false

- name: A guest network
  workshop144.calix_exos.wifi_secondary_network:
    host: 192.0.2.1
    password: "{{ router_password }}"
    ssid: guests
    key: "{{ guest_wifi_key }}"
```

`module_defaults` saves repeating `host` and `password`:

```yaml
- hosts: localhost
  module_defaults:
    group/workshop144.calix_exos.all:
      host: 192.0.2.1
      password: "{{ router_password }}"
```

## Development

The repository root is the collection root, so clone it to a path ending in
`ansible_collections/workshop144/calix_exos`. From there:

```
ansible-test sanity --venv
ansible-test units --venv -v
```

`tests/live/` holds a smoke test to run by hand against a real router; see its README.
`docs/api-notes.md` records what is known about the router's interface.

## Licence

GPL-3.0-or-later. See `LICENSE`.
