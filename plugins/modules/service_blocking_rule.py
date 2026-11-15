#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: service_blocking_rule
short_description: Manage a named set of ports for service blocking on a Calix EXOS router
version_added: "0.2.0"
description:
  - Manages one custom service on Advanced > Parental Control > Service Blocking in the router's
    admin page. A service is a name for one or more ports or port ranges. The
    M(workshop144.calix_exos.service_blocking) module then blocks a service for a device.
  - The ports of the service are made to match O(ports) exactly.
  - After a change the module reads the service back and fails if the router does not show what
    was asked for.
author:
  - Workshop 144 (@workshop144)
options:
  name:
    description:
      - Name of the service. It starts with a letter and has at most 14 letters, digits, hyphens
        and underscores.
    type: str
    required: true
  ports:
    description:
      - The ports the service covers. Required when O(state=present).
    type: list
    elements: dict
    suboptions:
      protocol:
        description:
          - Protocol of the ports.
        type: str
        choices: [tcp, udp, both]
        default: tcp
      port:
        description:
          - The port, or the first port of a range.
        type: int
        required: true
      port_end:
        description:
          - The last port of a range. Defaults to O(ports[].port).
        type: int
  state:
    description:
      - Whether the service should exist. The router refuses to remove one that is still blocked
        for a device.
    type: str
    choices: [present, absent]
    default: present
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
  - The router refuses changes to parental controls while the provider's app manages them. The
    module then fails without changing anything.
"""

EXAMPLES = r"""
- name: A service for one game
  workshop144.calix_exos.service_blocking_rule:
    host: 192.0.2.1
    password: "{{ router_password }}"
    name: thegame
    ports:
      - {protocol: both, port: 27015, port_end: 27030}
"""

RETURN = r"""
rule:
  description: The service after the run (in check mode, as it would be), or null.
  returned: always
  type: dict
  sample: {"name": "thegame", "ports": [{"protocol": "both", "port": 27015, "port_end": 27030}]}
"""

import re

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module

WIRE = {"tcp": "tcp", "udp": "udp", "both": "tcpudp"}


def _key(entry):
    return (entry["port"], entry["port_end"], entry["protocol"])


def _wanted_ports(ports):
    if not ports:
        raise ExosModuleError("ports must list at least one port")
    out = []
    for entry in ports:
        first = settings.port(entry.get("port"))
        last = settings.port(entry["port_end"], "port_end") if entry.get("port_end") else first
        if last < first:
            raise ExosModuleError("port_end %d is below port %d" % (last, first))
        out.append({"protocol": entry.get("protocol") or "tcp", "port": first, "port_end": last})
    return sorted({_key(e): e for e in out}.values(), key=_key)


def _public(rule):
    return {"name": rule["name"], "ports": sorted(rule["ports"], key=_key)} if rule else None


def _send(client, action, name, entry):
    client.call_text("serviceBlockingRule.cmd", action=action, ruleName=name, protocol=WIRE[entry["protocol"]],
                     portStart=entry["port"], portEnd=entry["port_end"], isCustom="1")


def run(params, client, check_mode):
    name = str(params["name"])
    if not re.fullmatch(r"[a-zA-Z][0-9a-zA-Z\-_]{0,13}", name):
        raise ExosModuleError("not a service name the router accepts: %r" % (params["name"],))
    present = params["state"] == "present"
    after = {"name": name, "ports": _wanted_ports(params.get("ports"))} if present else None
    with client:
        current = settings.read_service_rules(client).get(name)
        if current and not current["custom"]:
            raise ExosModuleError("%s is one of the router's built-in services and cannot be changed" % name)
        before = _public(current)
        if before != after:
            settings.require_local_parental_controls(client)
        if before != after and not check_mode:
            have = {_key(e): e for e in (before["ports"] if before else [])}
            want = {_key(e): e for e in (after["ports"] if after else [])}
            for key in sorted(set(want) - set(have)):
                _send(client, "add", name, want[key])
            for key in sorted(set(have) - set(want)):
                _send(client, "remove", name, have[key])
            now = _public(settings.read_service_rules(client).get(name))
            if now != after:
                raise ExosModuleError("the router accepted the service change but reports %r for %s" % (now, name))
    return changed_result(before, after, rule=after)


def main():
    run_module(
        dict(
            name=dict(type="str", required=True),
            ports=dict(type="list", elements="dict", options=dict(
                protocol=dict(type="str", default="tcp", choices=["tcp", "udp", "both"]),
                port=dict(type="int", required=True),
                port_end=dict(type="int"),
            )),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        ),
        run,
        required_if=[("state", "present", ("ports",))],
    )


if __name__ == "__main__":
    main()
