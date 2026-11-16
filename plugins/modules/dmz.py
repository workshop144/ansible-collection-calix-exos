#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: dmz
short_description: Set or clear the DMZ host on a Calix EXOS router
version_added: "0.2.0"
description:
  - A DMZ host receives every inbound connection the router has no other rule for. The router
    holds at most one.
  - Setting a different host removes the current one first. After a change the module reads the
    setting back and fails if the router does not show it.
author:
  - Workshop 144 (@workshop144)
options:
  dmz_host:
    description:
      - IPv4 address of the device on the LAN. Required when O(state=present).
    type: str
  state:
    description:
      - V(present) sets O(dmz_host) as the DMZ host; V(absent) clears whatever is set.
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
- name: Send unmatched inbound connections to one device
  workshop144.calix_exos.dmz:
    host: 192.0.2.1
    password: "{{ router_password }}"
    dmz_host: 192.0.2.50

- name: No DMZ host
  workshop144.calix_exos.dmz:
    host: 192.0.2.1
    password: "{{ router_password }}"
    state: absent
"""

RETURN = r"""
dmz_host:
  description: The DMZ host after the run (in check mode, as it would be), or null.
  returned: always
  type: str
  sample: 192.0.2.50
"""

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError


def _put_back(client, old, new, cause):
    """The new host was refused after the old one was removed: restore the old one and say so."""
    what = "could not set %s as the DMZ host (%s)" % (new, cause)
    try:
        client.call_text("scdmz.cmd", action="add", address=old)
        restored = settings.read_dmz(client) == old
    except ExosError:
        restored = False
    if restored:
        raise ExosModuleError("%s; the old DMZ host %s was restored" % (what, old)) from None
    raise ExosModuleError("%s, and %s could not be put back: there is now no DMZ host" % (what, old)) from None


def run(params, client, check_mode):
    wanted = settings.ipv4(params["dmz_host"], "DMZ host") if params["state"] == "present" else None
    with client:
        before = settings.read_dmz(client)
        if before != wanted and not check_mode:
            if before:
                client.call_text("scdmz.cmd", action="remove", address=before)
            if wanted:
                try:
                    client.call_text("scdmz.cmd", action="add", address=wanted)
                except ExosError as err:
                    if not before:
                        raise
                    _put_back(client, before, wanted, err)
            now = settings.read_dmz(client)
            if now != wanted:
                raise ExosModuleError("the router accepted the DMZ change but reports %r" % (now,))
    return changed_result(before, wanted, dmz_host=wanted)


def main():
    run_module(
        dict(dmz_host=dict(type="str"), state=dict(type="str", default="present", choices=["present", "absent"])),
        run,
        required_if=[("state", "present", ("dmz_host",))],
    )


if __name__ == "__main__":
    main()
