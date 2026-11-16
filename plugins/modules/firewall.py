#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: firewall
short_description: Set the firewall level and stealth mode of a Calix EXOS router
version_added: "0.2.0"
description:
  - Sets the router's firewall security level and whether it ignores unsolicited traffic from
    the internet (stealth mode), as on Advanced > Security > Firewall in its admin page.
  - Each level blocks a fixed set of services in each direction. The module sends the same table
    for a level that the admin page does.
  - Only the options given are changed. After a change the module reads the setting back and
    fails if the router does not show it.
author:
  - Workshop 144 (@workshop144)
options:
  level:
    description:
      - The security level. V(off) is the page's "Security Off".
    type: str
    choices: ["off", low, medium, high]
  stealth_mode:
    description:
      - Whether stealth mode is on.
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
- name: Highest level, stealth on
  workshop144.calix_exos.firewall:
    host: 192.0.2.1
    password: "{{ router_password }}"
    level: high
    stealth_mode: true
"""

RETURN = r"""
firewall:
  description: The setting after the run (in check mode, as it would be).
  returned: always
  type: dict
  sample: {"level": "high", "stealth_mode": true}
"""

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module
from ansible_collections.workshop144.calix_exos.plugins.module_utils.firewall_table import LEVELS, firewall_info


def run(params, client, check_mode):
    if params.get("level") is None and params.get("stealth_mode") is None:
        raise ExosModuleError("give at least one of level, stealth_mode")
    with client:
        before = settings.read_firewall(client)
        wanted = dict(before)
        if params.get("level") is not None:
            wanted["level"] = params["level"]
        if params.get("stealth_mode") is not None:
            wanted["stealth_mode"] = bool(params["stealth_mode"])
        if before != wanted and not check_mode:
            wire = LEVELS[wanted["level"]]
            fields = {
                "currentPage": "advanced_security_firewallsettings.html",
                "fwLevel": wire,
                "fwStealthMode": "1" if wanted["stealth_mode"] else "0",
                "firewallInfo": firewall_info(wire),
            }
            key = client.call(settings.PARAMS, action="get", ejGetOtherVal="sessionKey")
            if isinstance(key, dict) and key.get("sessionKey"):
                fields["sessionKey"] = key["sessionKey"]
            client.call_text("advanced_firewallsettings.cmd", **fields)
            now = settings.read_firewall(client)
            if now != wanted:
                raise ExosModuleError("the router accepted the firewall change but reports %s" % now)
    return changed_result(before, wanted, firewall=wanted)


def main():
    run_module(
        dict(level=dict(type="str", choices=["off", "low", "medium", "high"]), stealth_mode=dict(type="bool")),
        run,
    )


if __name__ == "__main__":
    main()
