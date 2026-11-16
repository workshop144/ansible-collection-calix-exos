#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: upnp
short_description: Turn UPnP on or off on a Calix EXOS router
version_added: "0.2.0"
description:
  - Sets whether the router answers UPnP requests from devices on the LAN, and whether UPnP NAT
    traversal (automatic port opening) is allowed.
  - After a change the module reads the setting back and fails if the router does not show it.
author:
  - Workshop 144 (@workshop144)
options:
  enabled:
    description:
      - Whether UPnP is on.
    type: bool
    required: true
  nat_t:
    description:
      - Whether UPnP NAT traversal is on. It needs O(enabled=true).
      - When not given it follows O(enabled).
    type: bool
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
- name: UPnP off
  workshop144.calix_exos.upnp:
    host: 192.0.2.1
    password: "{{ router_password }}"
    enabled: false
"""

RETURN = r"""
upnp:
  description: The setting after the run (in check mode, as it would be).
  returned: always
  type: dict
  sample: {"enabled": false, "nat_t": false}
"""

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module


def run(params, client, check_mode):
    enabled = bool(params["enabled"])
    nat_t = enabled if params.get("nat_t") is None else bool(params["nat_t"])
    if nat_t and not enabled:
        raise ExosModuleError("nat_t needs enabled=true: NAT traversal is part of UPnP")
    wanted = {"enabled": enabled, "nat_t": nat_t}
    with client:
        before = settings.read_upnp(client)
        if before != wanted and not check_mode:
            settings.write_upnp(client, enabled, nat_t)
            now = settings.read_upnp(client)
            if now != wanted:
                raise ExosModuleError("the router accepted the UPnP change but reports %s" % now)
    return changed_result(before, wanted, upnp=wanted)


def main():
    run_module(dict(enabled=dict(type="bool", required=True), nat_t=dict(type="bool")), run)


if __name__ == "__main__":
    main()
