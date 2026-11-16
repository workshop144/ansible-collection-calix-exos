#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: service_blocking
short_description: Block a service for one device on a Calix EXOS router
version_added: "0.2.0"
description:
  - Blocks one service, a named set of ports, for one device on the LAN (Advanced > Parental
    Control > Service Blocking in the router's admin page). The service is one of the router's
    built-in ones or one made with M(workshop144.calix_exos.service_blocking_rule).
  - After a change the module reads the list back and fails if the router does not show what was
    asked for.
author:
  - Workshop 144 (@workshop144)
options:
  ip:
    description:
      - IPv4 address of the device. It must be on the router's LAN.
    type: str
    required: true
  rule:
    description:
      - Name of the service to block.
    type: str
    required: true
  state:
    description:
      - Whether the service is blocked for the device.
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
  - The router can stop answering for up to a minute while it applies a change here. The module
    waits for it.
"""

EXAMPLES = r"""
- name: No game for that device
  workshop144.calix_exos.service_blocking:
    host: 192.0.2.1
    password: "{{ router_password }}"
    ip: 192.0.2.50
    rule: thegame
"""

RETURN = r"""
blocked:
  description: The device and service after the run (in check mode, as it would be), or null.
  returned: always
  type: dict
  sample: {"ip": "192.0.2.50", "rule": "thegame"}
"""

import ipaddress
import time

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError


def run(params, client, check_mode, sleep=time.sleep):
    wanted = {"ip": settings.ipv4(params["ip"], "ip"), "rule": str(params["rule"])}
    present = params["state"] == "present"
    with client:
        before = dict(wanted) if wanted in settings.read_service_blocks(client) else None
        after = dict(wanted) if present else None
        if before != after:
            settings.require_local_parental_controls(client)
            if present:
                if wanted["rule"] not in settings.read_service_rules(client):
                    raise ExosModuleError("the router has no service named %s" % wanted["rule"])
                lan = settings.params(client, names=("ethIpAddress", "ethSubnetMask"))
                network = ipaddress.ip_network("%s/%s" % (lan["ethIpAddress"], lan["ethSubnetMask"]), strict=False)
                if ipaddress.ip_address(wanted["ip"]) not in network:
                    raise ExosModuleError("%s is not on the router's LAN (%s)" % (wanted["ip"], network))
        if before != after and not check_mode:
            if present:
                client.call_text("serviceBlockingAssociation.cmd", action="add", ruleName=wanted["rule"], ipAddress=wanted["ip"])
            else:
                client.call_text("serviceBlockingAssociation.cmd", action="remove", ipAddress=wanted["ip"], ruleName=wanted["rule"])
            now, quiet = None, None
            for dummy in range(12):   # the router takes a moment to show the change, and can go quiet while it applies it
                sleep(2)
                try:
                    now = dict(wanted) if wanted in settings.read_service_blocks(client) else None
                except ExosError as err:
                    if not err.unreachable:
                        raise
                    quiet = err
                    continue
                quiet = None
                if now == after:
                    break
            if quiet is not None:
                raise ExosModuleError("the change was sent, but the router stopped answering afterwards: %s" % quiet)
            if now != after:
                raise ExosModuleError("the router accepted the change but does not show it")
    return changed_result(before, after, blocked=after)


def main():
    run_module(
        dict(
            ip=dict(type="str", required=True),
            rule=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        ),
        run,
    )


if __name__ == "__main__":
    main()
