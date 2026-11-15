#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: info
short_description: Read the state of a Calix EXOS router
version_added: "0.1.0"
description:
  - Logs in to the local web interface of a Calix EXOS router (the GigaSpire family) and returns
    its system, LAN, DHCP reservation, client, Wi-Fi, security and WAN state.
  - Changes nothing on the router. Passwords and Wi-Fi keys are never returned.
  - Values are returned as booleans, integers and lower-case MAC addresses so that a playbook can
    compare them with what it expects, to detect drift.
author:
  - Workshop 144 (@workshop144)
options:
  gather_subset:
    description:
      - Which parts of the state to read. V(all) reads everything.
    type: list
    elements: str
    choices: [all, system, lan, dhcp, dhcp_reservations, clients, ports, wifi, radios, security, firewall_rules,
              dns_host_mappings, ddns, arp_spoofing, controls, ipv6_lan, access_schedules, service_blocking, wan,
              internet]
    default: [all]
extends_documentation_fragment:
  - workshop144.calix_exos.connection
attributes:
  check_mode:
    support: full
    description: The module never changes anything, so check mode behaves the same.
  diff_mode:
    support: none
    description: Nothing is changed, so there is nothing to diff.
"""

EXAMPLES = r"""
- name: Read everything
  workshop144.calix_exos.info:
    host: 192.0.2.1
    password: "{{ router_password }}"
  register: router

- name: UPnP must be off and nothing forwarded
  ansible.builtin.assert:
    that:
      - not router.exos.security.upnp
      - router.exos.security.port_forwards | length == 0
      - router.exos.security.dmz_host is none

- name: Read only the reservations
  workshop144.calix_exos.info:
    host: 192.0.2.1
    password: "{{ router_password }}"
    gather_subset: [dhcp_reservations]
"""

RETURN = r"""
exos:
  description: The router's state, one key per subset that was read.
  returned: always
  type: dict
  contains:
    system:
      description: Model, serial, FSAN, EXOS version, uptime, mode, role and host name.
      type: dict
      sample: {"model": "GS4227W", "serial": "000000000000", "fsan": "CXNK00000000", "version": "25.4.0",
               "uptime": "3D 0H 59M 58S", "mode": "RG", "role": "Controller", "hostname": "router"}
    lan:
      description: The router's LAN address and DHCP pool.
      type: dict
      sample: {"address": "192.0.2.1", "netmask": "255.255.255.0", "dhcp_enabled": true,
               "pool_start": "192.0.2.100", "pool_end": "192.0.2.249", "lease_seconds": 43200}
    dhcp_reservations:
      description: Reserved addresses, sorted by address.
      type: list
      elements: dict
      sample: [{"pool": "lan", "mac": "02:00:00:00:00:aa", "ip": "192.0.2.150"}]
    clients:
      description: Devices the router knows about on IPv4.
      type: list
      elements: dict
      sample: [{"mac": "02:00:00:00:00:aa", "ip": "192.0.2.150", "name": "printer", "type": "Printer",
                "interface": "Ethernet", "active": true}]
    wifi:
      description:
        - One entry per network name per band. No key material.
        - The C(hidden) and C(isolation) keys are null when the router does not report them for
          a network (it does not for a guest network), and C(band) is null for a network it lists
          without a band or a status.
        - C(network_type) is V(guest) for a guest network, with its own C(gateway); both are null
          for a primary network.
        - The C(wps) and C(wps_type) keys are null for a network the router does not report a
          status for.
      type: list
      elements: dict
      sample: [{"band": "5GHz", "ssid": "example", "enabled": true, "hidden": false,
                "security": "psk-mixed+aes", "wps": true, "wps_type": "PushButton", "isolation": false,
                "network_type": null, "gateway": null}]
    security:
      description:
        - UPnP, firewall, DMZ and port forwarding state.
        - Each entry of C(port_forwards) has the keys the M(workshop144.calix_exos.port_forward)
          module returns.
      type: dict
      sample: {"upnp": false, "upnp_nat": false, "firewall_level": "High", "stealth_mode": true,
               "dmz_host": null, "port_forwards": []}
      contains:
        dmz_host:
          description:
            - Null when no DMZ host is set. Otherwise the host, or whatever the router returns for
              its DMZ setting.
          type: raw
    wan:
      description: WAN connection status as the router reports it.
      type: dict
      sample: {"wan": {"state": 2, "color": "green"}, "ipv4": {"state": 2, "color": "green"}}
    dhcp:
      description: The DHCP server and LAN address, as the M(workshop144.calix_exos.dhcp) module returns them.
      type: dict
    ports:
      description: The Ethernet ports and whether each has a link.
      type: list
      elements: dict
      sample: [{"port": 1, "type": "Ethernet", "rate": "1000M", "connected": true}]
    radios:
      description: The Wi-Fi radios, each as the M(workshop144.calix_exos.wifi_radio) module returns it.
      type: list
      elements: dict
    firewall_rules:
      description:
        - Custom firewall rules by chain (C(ipv4_in), C(ipv4_out), C(ipv6_in), C(ipv6_out)), in match order, each as
          the M(workshop144.calix_exos.firewall_rule) module returns it.
      type: dict
    dns_host_mappings:
      description: Local DNS names, each with C(hostname) and C(ip).
      type: list
      elements: dict
    ddns:
      description: The dynamic DNS client for C(ipv4) and C(ipv6). The password is never returned.
      type: dict
      sample: {"ipv4": {"enabled": false, "server": null, "user": null, "hostname": null, "ip_source": null,
                        "website": null}}
    arp_spoofing:
      description: Whether ARP spoofing protection is on.
      type: bool
    controls:
      description: LED and SIP ALG, as the M(workshop144.calix_exos.controls) module returns them.
      type: dict
    ipv6_lan:
      description: IPv6 on the LAN, as the M(workshop144.calix_exos.ipv6_lan) module returns it.
      type: dict
    access_schedules:
      description: Times at which devices are cut off from the internet. No days means always.
      type: list
      elements: dict
      sample: [{"mac": "02:00:00:00:00:aa", "days": ["mon", "sat"], "start": "22:00", "end": "23:30"}]
    service_blocking:
      description: The services that can be blocked (C(rules)) and which device each is blocked for (C(blocked)).
      type: dict
    internet:
      description:
        - The Status > Internet page, in sections C(status), C(settings), C(ipv4) and C(ipv6). Keys are the page's
          own labels in lower case with underscores.
      type: dict
      sample: {"ipv4": {"device_ipv4_address": "198.51.100.20"}}
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.workshop144.calix_exos.plugins.module_utils import normalize, settings, wifi
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import (
    EXOS_ARGUMENT_SPEC,
    ExosError,
    client_from_module,
)

LAN_PARAMS = ",".join(normalize.LAN_PARAMS)
SECURITY_PARAMS = ",".join(normalize.SECURITY_PARAMS)
SECURITY_OTHER_PARAMS = ",".join(normalize.SECURITY_OTHER_PARAMS)


def _system(client):
    return normalize.system(client.call("status_system.cmd", action="get"))


def _lan(client):
    return normalize.lan(client.call("cgi_parameter_value.cmd", action="get", ejGetVal=LAN_PARAMS))


def _dhcp_reservations(client):
    return normalize.reservations(client.call("dhcp_reservation.cmd", action="init"))


def _clients(client):
    return normalize.clients(client.call("device_table.cmd", action="get"))


def _wifi(client):
    status = client.call("wlinfo.cmd", action="get_status")
    ssids = []
    for usage in ("primary", "guest"):
        rows = client.call("wlinfo.cmd", action="get_ssid_setup", wlSsidUsage=usage)
        if isinstance(rows, list):
            ssids.extend(rows)
    return normalize.wifi(status, ssids)


def _security(client):
    params = client.call("cgi_parameter_value.cmd", action="get", ejGetVal=SECURITY_PARAMS)
    other = client.call("cgi_parameter_value.cmd", action="get", ejGetOtherVal=SECURITY_OTHER_PARAMS)
    params = dict(params if isinstance(params, dict) else {}, **(other if isinstance(other, dict) else {}))
    forwards = [settings.public_rule(rule) for rule in settings.read_port_forwards(client)]
    return normalize.security(params, None, forwards)


def _wan(client):
    return normalize.wan(client.call("status_connection.cmd", action="getStatus"))


def _dhcp(client):
    return settings.public_dhcp(settings.params(client, names=settings.DHCP_NAMES))


def _firewall_rules(client):
    return {
        chain: [settings.public_firewall_rule(chain, raw) for raw in settings.read_chain(client, chain)]
        for chain in settings.CHAINS
    }


def _access_schedules(client):
    return [{key: value for key, value in entry.items() if not key.startswith("_")}
            for entry in settings.read_access_schedules(client)]


def _service_blocking(client):
    rules = settings.read_service_rules(client)
    return {"rules": [rules[name] for name in sorted(rules)], "blocked": settings.read_service_blocks(client)}


def _radios(client):
    return [wifi.public_radio(raw) for raw in wifi.radios(client)]


def _ipv6_lan(client):
    return settings.public_ipv6_lan(settings.read_ipv6_lan_raw(client))


READERS = {
    "dhcp": _dhcp,
    "ports": settings.read_ports,
    "radios": _radios,
    "firewall_rules": _firewall_rules,
    "dns_host_mappings": settings.read_dns_mappings,
    "ddns": settings.read_ddns,
    "arp_spoofing": settings.read_arp_spoofing,
    "controls": settings.read_controls,
    "ipv6_lan": _ipv6_lan,
    "access_schedules": _access_schedules,
    "service_blocking": _service_blocking,
    "internet": settings.read_internet,
    "system": _system,
    "lan": _lan,
    "dhcp_reservations": _dhcp_reservations,
    "clients": _clients,
    "wifi": _wifi,
    "security": _security,
    "wan": _wan,
}


def run(params, client):
    """Log in, read the requested subsets, log out."""
    wanted = params.get("gather_subset") or ["all"]
    subsets = [name for name in normalize.SUBSETS if "all" in wanted or name in wanted]
    with client:
        exos = {name: READERS[name](client) for name in subsets}
    return {"changed": False, "exos": exos}


def main():
    argument_spec = dict(EXOS_ARGUMENT_SPEC)
    argument_spec.update(
        gather_subset=dict(type="list", elements="str", default=["all"], choices=["all"] + list(normalize.SUBSETS)),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    try:
        result = run(module.params, client_from_module(module))
    except ExosError as err:
        module.fail_json(msg=str(err), code=err.code, endpoint=err.endpoint)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
