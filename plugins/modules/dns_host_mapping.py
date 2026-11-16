#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: dns_host_mapping
short_description: Manage one local DNS name on a Calix EXOS router
version_added: "0.2.0"
description:
  - Makes the router's DNS server answer a name with an address of your choosing, for devices
    that use the router for DNS.
  - A mapping is identified by its name. Asking for a different address for a name that already
    has one replaces it.
  - After a change the module reads the table back and fails if the router does not show what
    was asked for.
author:
  - Workshop 144 (@workshop144)
options:
  hostname:
    description:
      - The name, for example V(printer.home.example). Letters, digits and hyphens in each label,
        at most 63 characters.
    type: str
    required: true
  ip:
    description:
      - IPv4 address the name should resolve to. Required when O(state=present).
      - It cannot be the router's own address.
    type: str
  state:
    description:
      - Whether the mapping should exist.
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
- name: A name for the printer
  workshop144.calix_exos.dns_host_mapping:
    host: 192.0.2.1
    password: "{{ router_password }}"
    hostname: printer.home.example
    ip: 192.0.2.50
"""

RETURN = r"""
mapping:
  description: The mapping after the run (in check mode, as it would be), or null.
  returned: always
  type: dict
  sample: {"hostname": "printer.home.example", "ip": "192.0.2.50"}
"""

import re
import time

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import (
    ExosModuleError,
    add_when_ready,
    changed_result,
    run_module,
)
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError

LABELS = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")


def _hostname(value):
    name = str(value).strip()
    if len(name) > 63 or not LABELS.match(name) or not re.search(r"[a-zA-Z\-]", name):
        raise ExosModuleError("not a host name the router accepts: %r" % (value,))
    return name


def _find(table, name):
    return next((row for row in table if row["hostname"].lower() == name.lower()), None)


def _put_back(client, old, cause):
    """The new address was refused after the old mapping was removed: restore it and say so."""
    what = "could not map %s to the new address (%s)" % (old["hostname"], cause)
    try:
        client.call_text("dns_host_mapping.cmd", action="add", hostName=old["hostname"], ip=old["ip"])
        restored = _find(settings.read_dns_mappings(client), old["hostname"]) == old
    except ExosError:
        restored = False
    if restored:
        raise ExosModuleError("%s; the old mapping to %s was restored" % (what, old["ip"])) from None
    raise ExosModuleError("%s, and the old mapping could not be put back: the name is no longer mapped" % what) from None


def run(params, client, check_mode, sleep=time.sleep):
    name = _hostname(params["hostname"])
    present = params["state"] == "present"
    after = {"hostname": name, "ip": settings.ipv4(params["ip"], "ip")} if present else None
    with client:
        before = _find(settings.read_dns_mappings(client), name)
        same = before is not None and after is not None and before["ip"] == after["ip"]
        if same:
            after = before
        if present and not same:
            own = settings.params(client, names=("ethIpAddress",))["ethIpAddress"]
            if after["ip"] == own:
                raise ExosModuleError("%s is the router's own address and cannot be mapped" % own)
        if before != after and not check_mode:
            if before:
                client.call_text("dns_host_mapping.cmd", action="del", hostName=before["hostname"], ip=before["ip"])
            if after:
                try:
                    add_when_ready(
                        lambda: client.call_text("dns_host_mapping.cmd", action="add", hostName=after["hostname"], ip=after["ip"]),
                        lambda: _find(settings.read_dns_mappings(client), name) == after,
                        sleep,
                    )
                except ExosError as err:
                    if not before:
                        raise
                    _put_back(client, before, err)
            now = _find(settings.read_dns_mappings(client), name)
            if now != after:
                raise ExosModuleError("the router accepted the DNS mapping change but reports %r for %s" % (now, name))
    return changed_result(before, after, mapping=after)


def main():
    run_module(
        dict(
            hostname=dict(type="str", required=True),
            ip=dict(type="str"),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        ),
        run,
        required_if=[("state", "present", ("ip",))],
    )


if __name__ == "__main__":
    main()
