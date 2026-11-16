#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: port_forward
short_description: Manage one port forwarding rule on a Calix EXOS router
version_added: "0.2.0"
description:
  - Forwards a port, or a range of ports, arriving at the router from the internet to a device on
    the LAN.
  - A rule is identified by its protocol, its internet-side ports and its source address. Asking
    for a different LAN device or LAN port for the same internet-side ports replaces the rule.
  - After a change the module reads the rules back and fails if the router does not show what was
    asked for.
author:
  - Workshop 144 (@workshop144)
options:
  protocol:
    description:
      - Which protocol to forward.
    type: str
    choices: [tcp, udp, both]
    default: tcp
  remote_port:
    description:
      - First internet-side port. Defaults to O(local_port).
      - The router keeps ports 60000-60100, and TCP 8443 and 30005-30007, for itself.
    type: int
  remote_port_end:
    description:
      - Last internet-side port of a range. Defaults to O(remote_port).
    type: int
  remote_ip:
    description:
      - Forward only connections from this internet address. Any address when not given.
    type: str
  local_ip:
    description:
      - IPv4 address of the device on the LAN. Required when O(state=present).
    type: str
  local_port:
    description:
      - First port on the device. Required when O(state=present).
    type: int
  local_port_end:
    description:
      - Last port on the device, for a range. The range must be as wide as the internet-side one.
        Defaults to a range of that width.
    type: int
  state:
    description:
      - Whether the rule should exist.
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
"""

EXAMPLES = r"""
- name: Web server on the LAN, reachable on port 8080 from outside
  workshop144.calix_exos.port_forward:
    host: 192.0.2.1
    password: "{{ router_password }}"
    protocol: tcp
    remote_port: 8080
    local_ip: 192.0.2.50
    local_port: 80

- name: Remove it
  workshop144.calix_exos.port_forward:
    host: 192.0.2.1
    password: "{{ router_password }}"
    protocol: tcp
    remote_port: 8080
    state: absent
"""

RETURN = r"""
rule:
  description: The rule after the run (in check mode, as it would be), or null.
  returned: always
  type: dict
  sample: {"protocol": "tcp", "local_ip": "192.0.2.50", "local_port": 80, "local_port_end": 80,
           "remote_ip": null, "remote_port": 8080, "remote_port_end": 8080}
"""

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError

RESERVED_ANY = range(60000, 60101)
RESERVED_TCP = (8443, 30005, 30006, 30007)


def _wanted(params):
    protocol = params["protocol"]
    absent = params["state"] == "absent"
    first = params["remote_port"] if params["remote_port"] is not None else params["local_port"]
    if first is None:
        raise ExosModuleError("remote_port or local_port is required")
    remote_start = settings.port(first, "remote_port")
    remote_end = settings.port(params["remote_port_end"], "remote_port_end") if params["remote_port_end"] else remote_start
    if remote_end < remote_start:
        raise ExosModuleError("remote_port_end is below remote_port")
    remote_ip = settings.ipv4(params["remote_ip"], "remote_ip") if params.get("remote_ip") else None
    rule = {"protocol": protocol, "remote_ip": remote_ip, "remote_port": remote_start, "remote_port_end": remote_end}
    if absent:
        return rule
    for number in range(remote_start, remote_end + 1):
        if number in RESERVED_ANY or (protocol in ("tcp", "both") and number in RESERVED_TCP):
            raise ExosModuleError("the router keeps port %d for itself" % number)
    local_start = settings.port(params["local_port"], "local_port")
    width = remote_end - remote_start
    local_end = settings.port(params["local_port_end"], "local_port_end") if params["local_port_end"] else local_start + width
    if local_end - local_start != width:
        raise ExosModuleError("the local and the remote port ranges must be the same width")
    rule.update(local_ip=settings.ipv4(params["local_ip"], "local_ip"), local_port=local_start, local_port_end=local_end)
    return rule


def _same_identity(rule, wanted):
    return all(rule[key] == wanted[key] for key in ("protocol", "remote_ip", "remote_port", "remote_port_end"))


def _find(rules, wanted):
    return next((rule for rule in rules if _same_identity(rule, wanted)), None)


def _put_back(client, old, cause):
    """The new rule was refused after the old one was removed: restore the old one and say so."""
    what = "could not add the new rule (%s)" % cause
    try:
        client.call_text("advancedPortForwarding.cmd", action="add",
                         **settings.port_forward_fields(old, remote_raw=old["_remote_raw"]))
        restored = _find(settings.read_port_forwards(client), old) is not None
    except ExosError:
        restored = False
    if restored:
        raise ExosModuleError("%s; the old rule was restored" % what) from None
    raise ExosModuleError("%s, and the old rule could not be put back: the port is no longer forwarded" % what) from None


def run(params, client, check_mode):
    wanted = _wanted(params)
    present = params["state"] == "present"
    with client:
        existing = _find(settings.read_port_forwards(client), wanted)
        before = settings.public_rule(existing) if existing else None
        after = dict(wanted) if present else None
        if before != after and not check_mode:
            if existing:
                fields = settings.port_forward_fields(existing, remote_raw=existing["_remote_raw"])
                client.call_text("advancedPortForwarding.cmd", action="remove", **fields)
            if present:
                try:
                    client.call_text("advancedPortForwarding.cmd", action="add", **settings.port_forward_fields(wanted))
                except ExosError as err:
                    if not existing:
                        raise
                    _put_back(client, existing, err)
            found = _find(settings.read_port_forwards(client), wanted)
            now = settings.public_rule(found) if found else None
            if now != after:
                raise ExosModuleError("the router accepted the port forwarding change but reports %r for it" % (now,))
    return changed_result(before, after, rule=after)


def main():
    run_module(
        dict(
            protocol=dict(type="str", default="tcp", choices=["tcp", "udp", "both"]),
            remote_port=dict(type="int"),
            remote_port_end=dict(type="int"),
            remote_ip=dict(type="str"),
            local_ip=dict(type="str"),
            local_port=dict(type="int"),
            local_port_end=dict(type="int"),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        ),
        run,
        required_if=[("state", "present", ("local_ip", "local_port"))],
    )


if __name__ == "__main__":
    main()
