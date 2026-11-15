#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: arp_spoofing
short_description: Turn ARP spoofing protection on or off on a Calix EXOS router
version_added: "0.2.0"
description:
  - Sets the router's ARP spoofing protection (Advanced > Security > Arp Spoofing in its admin
    page).
  - After a change the module reads the setting back and fails if the router does not show it.
author:
  - Workshop 144 (@workshop144)
options:
  enabled:
    description:
      - Whether the protection is on.
    type: bool
    required: true
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
- name: ARP spoofing protection on
  workshop144.calix_exos.arp_spoofing:
    host: 192.0.2.1
    password: "{{ router_password }}"
    enabled: true
"""

RETURN = r"""
enabled:
  description: Whether the protection is on after the run (in check mode, as it would be).
  returned: always
  type: bool
  sample: true
"""

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module


def run(params, client, check_mode):
    wanted = bool(params["enabled"])
    with client:
        before = settings.read_arp_spoofing(client)
        if before != wanted and not check_mode:
            client.call_json("arp_spoof.cmd", {"action": "set", "admin": "1" if wanted else "0"})
            now = settings.read_arp_spoofing(client)
            if now != wanted:
                raise ExosModuleError("the router accepted the ARP spoofing change but reports %s" % now)
    return changed_result(before, wanted, enabled=wanted)


def main():
    run_module(dict(enabled=dict(type="bool", required=True)), run)


if __name__ == "__main__":
    main()
