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
    choices: [all, system, lan, dhcp_reservations, clients, wifi, security, wan]
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
        - The C(wps) and C(wps_type) keys are null for a network the router does not report a
          status for.
      type: list
      elements: dict
      sample: [{"band": "5GHz", "ssid": "example", "enabled": true, "hidden": false,
                "security": "psk-mixed+aes", "wps": true, "wps_type": "PushButton", "isolation": false}]
    security:
      description: UPnP, firewall, DMZ and port forwarding state.
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
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.workshop144.calix_exos.plugins.module_utils import normalize
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
    dmz = client.call("scdmz.cmd", action="get")
    forwards = client.call("portForwardingAssociations.cmd", action="readall")
    return normalize.security(params, dmz, forwards)


def _wan(client):
    return normalize.wan(client.call("status_connection.cmd", action="getStatus"))


READERS = {
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
