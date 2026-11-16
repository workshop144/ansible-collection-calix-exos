#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: dhcp
short_description: Set the DHCP server and LAN address of a Calix EXOS router
version_added: "0.2.0"
description:
  - Sets the DHCP server on the LAN (on or off, address pool, lease time, DNS servers handed
    out), the router's host and domain name, and, with O(force=true), the router's own LAN
    address and netmask (Advanced > IP Address > DHCP Settings in the router's admin page).
  - Only the options given are changed. After a change the module reads the settings back and
    fails if the router does not show them.
  - B(Changing the LAN address or netmask moves the router.) Every device loses it until it
    renews its lease, and the module can no longer reach it at O(host), so there is no read-back
    for that change. It is refused unless O(force=true).
author:
  - Workshop 144 (@workshop144)
options:
  enabled:
    description:
      - Whether the DHCP server is on.
    type: bool
  pool_start:
    description:
      - First address of the pool. It must be on the LAN and must not be the router's address.
    type: str
  pool_end:
    description:
      - Last address of the pool.
    type: str
  lease_seconds:
    description:
      - How long a lease lasts, at least 120 seconds.
    type: int
  dns_servers:
    description:
      - One or two IPv4 DNS servers to hand out. An empty list hands out the router itself.
    type: list
    elements: str
  hostname:
    description:
      - The router's own host name on the LAN.
    type: str
  domain:
    description:
      - The DNS domain of the LAN.
    type: str
  lan_address:
    description:
      - The router's own IPv4 address on the LAN. Needs O(force=true).
    type: str
  lan_netmask:
    description:
      - The LAN's netmask. Needs O(force=true).
    type: str
  force:
    description:
      - Allow a change of O(lan_address) or O(lan_netmask). The new address must be a private one
        the router's own page accepts.
    type: bool
    default: false
extends_documentation_fragment:
  - workshop144.calix_exos.connection
attributes:
  check_mode:
    support: full
    description: Reports what would change without sending any change to the router.
  diff_mode:
    support: full
    description: Shows the settings before and after.
notes:
  - The router restarts its DHCP and DNS service on a change; lookups can fail for a few seconds.
  - The router sends every setting of this page together, so the module reads them all first and
    sends back the ones it was not asked to change.
"""

EXAMPLES = r"""
- name: A twelve hour lease and our own DNS server
  workshop144.calix_exos.dhcp:
    host: 192.0.2.1
    password: "{{ router_password }}"
    lease_seconds: 43200
    dns_servers: [192.0.2.53]
"""

RETURN = r"""
dhcp:
  description: The settings after the run (in check mode, as they would be).
  returned: always
  type: dict
  sample: {"enabled": true, "pool_start": "192.0.2.100", "pool_end": "192.0.2.249", "lease_seconds": 43200,
           "dns_servers": [], "lan_address": "192.0.2.1", "lan_netmask": "255.255.255.0", "hostname": "router",
           "domain": "home.example"}
"""

import ipaddress
import re
import time

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module

LABEL = r"[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?"


RESERVED_THIRD_OCTETS = tuple(range(12, 19)) + tuple(range(22, 29)) + tuple(range(32, 39))   # the router's guest subnets


def _netmask(value):
    mask = int(ipaddress.IPv4Address(value))
    inverse = ~mask & 0xFFFFFFFF
    if mask == 0 or inverse & (inverse + 1):
        raise ExosModuleError("lan_netmask is not a netmask: %r" % (value,))


def _check_move(wanted, before):
    """A new LAN address must be one the router's own page would take."""
    _netmask(wanted["lan_netmask"])
    address = ipaddress.ip_address(wanted["lan_address"])
    current = ipaddress.ip_network("%s/%s" % (before["lan_address"], before["lan_netmask"]), strict=False)
    if address in current and wanted["lan_netmask"] == before["lan_netmask"]:
        return
    octets = [int(part) for part in wanted["lan_address"].split(".")]
    private = octets[0] == 10 or (octets[0] == 172 and 16 <= octets[1] <= 31) or (octets[0], octets[1]) == (192, 168)
    if not private:
        raise ExosModuleError("lan_address must be a private address (10.x, 172.16-31.x or 192.168.x)")
    if (octets[0], octets[1]) == (192, 168) and octets[2] in RESERVED_THIRD_OCTETS:
        raise ExosModuleError("192.168.%d.x is one of the ranges the router keeps for its secondary networks" % octets[2])
    if octets[0] == 172 and 28 <= octets[1] <= 31:
        raise ExosModuleError("172.%d.x.x is a range the router keeps for itself" % octets[1])


def _check(wanted):
    try:
        _check_values(wanted)
    except ValueError:
        raise ExosModuleError(
            "the DHCP pool or LAN address is not set to a usable address: give pool_start and pool_end"
        ) from None


def _check_values(wanted):
    try:
        network = ipaddress.ip_network("%s/%s" % (wanted["lan_address"], wanted["lan_netmask"]), strict=False)
    except ValueError:
        raise ExosModuleError("lan_address and lan_netmask do not make a network") from None
    router = ipaddress.ip_address(wanted["lan_address"])
    if router in (network.network_address, network.broadcast_address):
        raise ExosModuleError("lan_address cannot be the network or broadcast address")
    if not re.fullmatch(LABEL, wanted["hostname"]) or len(wanted["hostname"]) > 63:
        raise ExosModuleError("not a host name the router accepts: %r" % (wanted["hostname"],))
    if not re.fullmatch(r"%s(\.%s)*" % (LABEL, LABEL), wanted["domain"]) or len(wanted["domain"]) > 63:
        raise ExosModuleError("not a domain the router accepts: %r" % (wanted["domain"],))
    if len(wanted["dns_servers"]) > 2:
        raise ExosModuleError("the router hands out at most two DNS servers")
    if not wanted["enabled"]:
        return
    start, end = ipaddress.ip_address(wanted["pool_start"]), ipaddress.ip_address(wanted["pool_end"])
    for address, what in ((start, "pool_start"), (end, "pool_end")):
        if address not in network or address in (network.network_address, network.broadcast_address):
            raise ExosModuleError("%s must be a usable address on the LAN (%s)" % (what, network))
    if start > end:
        raise ExosModuleError("pool_start is above pool_end")
    if start <= router <= end:
        raise ExosModuleError("the router's own address cannot be inside the pool")
    if wanted["lease_seconds"] is None or not 120 <= wanted["lease_seconds"] <= 366 * 86400:
        raise ExosModuleError("lease_seconds must be at least 120")


def _fields(wanted, raw):
    fields = {
        "dnsHostName": wanted["hostname"],
        "dnsDomainName": wanted["domain"],
        "enblDhcpSrv": 1 if wanted["enabled"] else 0,
        "dhcpServerIP": wanted["lan_address"],
        "dhcpSubnetMask": wanted["lan_netmask"],
    }
    if wanted["enabled"]:
        servers = wanted["dns_servers"]
        fields.update(
            dhcpEthStart=wanted["pool_start"],
            dhcpEthEnd=wanted["pool_end"],
            dnsType="custom" if servers else "default",
            # for the default the admin page sends these two fixed addresses; the router ignores them
            dnsPrimary=servers[0] if servers else "192.168.1.1",
            dnsSecondary=(servers[1] if len(servers) > 1 else "0.0.0.0") if servers else "205.171.3.25",
            dhcpLeasedTime=wanted["lease_seconds"],
            dhcpAutoReserve=raw["enblDhcpReservation"],
        )
    fields.update(
        dhcpOptionTftpEn=raw["dhcpOptionTftpEn"],
        dhcpOptionTftpOpt66=raw["dhcpOptionTftpOpt66"],
        dhcpOptionTftpOpt150=raw["dhcpOptionTftpOpt150"],
    )
    return fields


def run(params, client, check_mode, sleep=time.sleep):
    options = ("enabled", "pool_start", "pool_end", "lease_seconds", "dns_servers", "hostname", "domain", "lan_address", "lan_netmask")
    if all(params.get(name) is None for name in options):
        raise ExosModuleError("give at least one setting to change")
    with client:
        raw = settings.params(client, names=settings.DHCP_NAMES)
        before = settings.public_dhcp(raw)
        wanted = dict(before)
        for name in ("enabled", "lease_seconds", "hostname", "domain"):
            if params.get(name) is not None:
                wanted[name] = params[name]
        for name in ("pool_start", "pool_end", "lan_address", "lan_netmask"):
            if params.get(name) is not None:
                wanted[name] = settings.ipv4(params[name], name)
        if params.get("dns_servers") is not None:
            wanted["dns_servers"] = [settings.ipv4(server, "DNS server") for server in params["dns_servers"]]
            if "0.0.0.0" in wanted["dns_servers"]:
                raise ExosModuleError("0.0.0.0 is not a DNS server; give an empty list to hand out the router itself")
        pool_options = [name for name in ("pool_start", "pool_end", "lease_seconds", "dns_servers") if params.get(name) is not None]
        if not wanted["enabled"] and pool_options:
            raise ExosModuleError(
                "the DHCP server is off, so %s cannot be set; give enabled=true as well" % ", ".join(pool_options)
            )
        moves = (wanted["lan_address"], wanted["lan_netmask"]) != (before["lan_address"], before["lan_netmask"])
        if before != wanted:
            _check(wanted)
            if moves:
                _check_move(wanted, before)
            if moves and not params.get("force"):
                raise ExosModuleError(
                    "changing lan_address or lan_netmask moves the router and cuts this connection; set force=true to do it"
                )
        if before != wanted and not check_mode:
            client.call_text("dhcpcfg.cmd", **_fields(wanted, raw))
            if not moves:
                now = None
                for dummy in range(5):   # the DHCP service restarts; give it a moment
                    now = settings.public_dhcp(settings.params(client, names=settings.DHCP_NAMES))
                    if now == wanted:
                        break
                    sleep(2)
                if now != wanted:
                    raise ExosModuleError("the router accepted the DHCP change but reports %s" % now)
    return changed_result(before, wanted, dhcp=wanted)


def main():
    run_module(
        dict(
            enabled=dict(type="bool"),
            pool_start=dict(type="str"),
            pool_end=dict(type="str"),
            lease_seconds=dict(type="int"),
            dns_servers=dict(type="list", elements="str"),
            hostname=dict(type="str"),
            domain=dict(type="str"),
            lan_address=dict(type="str"),
            lan_netmask=dict(type="str"),
            force=dict(type="bool", default=False),
        ),
        run,
    )


if __name__ == "__main__":
    main()
