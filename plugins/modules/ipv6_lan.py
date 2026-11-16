#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: ipv6_lan
short_description: Set how a Calix EXOS router hands out IPv6 on the LAN
version_added: "0.2.0"
description:
  - Sets router advertisement, DHCPv6 and the IPv6 DNS servers given to devices on the LAN
    (Advanced > IP Address > IPv6 LAN Settings in the router's admin page).
  - Only the options given are changed. After a change the module reads the settings back and
    fails if the router does not show them.
author:
  - Workshop 144 (@workshop144)
options:
  router_advertisement:
    description:
      - Whether the router sends router advertisements.
    type: bool
  dhcpv6:
    description:
      - Whether the router runs a DHCPv6 server.
    type: bool
  dhcpv6_mode:
    description:
      - What DHCPv6 hands out.
    type: str
    choices: [stateless, stateful, both]
  dns_servers:
    description:
      - One or two IPv6 DNS servers to give to devices. An empty list goes back to the router's
        default.
    type: list
    elements: str
extends_documentation_fragment:
  - workshop144.calix_exos.connection
attributes:
  check_mode:
    support: full
    description: Reports what would change without sending any change to the router.
  diff_mode:
    support: full
    description: Shows the setting before and after.
notes:
  - Devices pick up a change when they next renew, so IPv6 on the LAN can be unsettled for a
    short while after one.
"""

EXAMPLES = r"""
- name: Stateless DHCPv6 with our own DNS servers
  workshop144.calix_exos.ipv6_lan:
    host: 192.0.2.1
    password: "{{ router_password }}"
    dhcpv6_mode: stateless
    dns_servers: ["2001:db8::53"]
"""

RETURN = r"""
ipv6_lan:
  description: The settings after the run (in check mode, as they would be).
  returned: always
  type: dict
  sample: {"router_advertisement": true, "dhcpv6": true, "dhcpv6_mode": "both", "dns_servers": []}
"""

import ipaddress

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module


def _dns(servers):
    if len(servers) > 2:
        raise ExosModuleError("the router takes at most two IPv6 DNS servers")
    out = []
    for server in servers:
        try:
            out.append(str(ipaddress.IPv6Address(str(server).strip())))
        except ValueError:
            raise ExosModuleError("not an IPv6 address: %r" % (server,)) from None
    return out


def run(params, client, check_mode):
    given = {key: params.get(key) for key in ("router_advertisement", "dhcpv6", "dhcpv6_mode", "dns_servers")}
    if all(value is None for value in given.values()):
        raise ExosModuleError("give at least one of router_advertisement, dhcpv6, dhcpv6_mode, dns_servers")
    dns = _dns(given["dns_servers"]) if given["dns_servers"] is not None else None
    with client:
        raw = settings.read_ipv6_lan_raw(client)
        before = settings.public_ipv6_lan(raw)
        wanted = dict(before)
        for key in ("router_advertisement", "dhcpv6", "dhcpv6_mode"):
            if given[key] is not None:
                wanted[key] = given[key]
        if dns is not None:
            wanted["dns_servers"] = dns
        if before != wanted and not check_mode:
            payload = dict(raw, action="apply")     # everything as the router gave it, then only what was asked
            if given["router_advertisement"] is not None:
                payload["ra"] = "server" if wanted["router_advertisement"] else "disabled"
            if given["dhcpv6"] is not None:
                payload["dhcpv6"] = "server" if wanted["dhcpv6"] else "disabled"
            if given["dhcpv6_mode"] is not None:
                payload["dhcpv6Mode"] = wanted["dhcpv6_mode"]
            if dns is not None:
                payload["dns6Type"] = "custom" if dns else "default"
                if dns:
                    payload["advPriDns"] = dns[0]
                    payload["advSecDns"] = dns[1] if len(dns) > 1 else ""
            if payload.get("dns6Type") != "custom":   # the admin page leaves these out for the default
                payload.pop("advPriDns", None)
                payload.pop("advSecDns", None)
            client.call_json("lan_setting_ipv6.cmd", payload)
            now = settings.public_ipv6_lan(settings.read_ipv6_lan_raw(client))
            if now != wanted:
                raise ExosModuleError("the router accepted the IPv6 LAN change but reports %s" % now)
    return changed_result(before, wanted, ipv6_lan=wanted)


def main():
    run_module(
        dict(
            router_advertisement=dict(type="bool"),
            dhcpv6=dict(type="bool"),
            dhcpv6_mode=dict(type="str", choices=["stateless", "stateful", "both"]),
            dns_servers=dict(type="list", elements="str"),
        ),
        run,
    )


if __name__ == "__main__":
    main()
