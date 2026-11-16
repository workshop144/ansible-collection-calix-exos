#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: controls
short_description: Set the LED and SIP ALG controls of a Calix EXOS router
version_added: "0.2.0"
description:
  - Sets the front LED (on, off and, where the router supports it, brightness) and the SIP
    application-level gateway (Advanced > Controls in the router's admin page).
  - Only the options given are changed. After a change the module reads the settings back and
    fails if the router does not show them.
author:
  - Workshop 144 (@workshop144)
options:
  led:
    description:
      - Whether the front LED is lit.
    type: bool
  brightness:
    description:
      - LED brightness in percent, in steps of 10. Only on routers with a dimmable LED, and only
        while the LED is on.
    type: int
  sip_alg:
    description:
      - Whether the SIP application-level gateway is on.
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
- name: Dim the LED and turn SIP ALG off
  workshop144.calix_exos.controls:
    host: 192.0.2.1
    password: "{{ router_password }}"
    brightness: 30
    sip_alg: false
"""

RETURN = r"""
controls:
  description:
    - The settings after the run (in check mode, as they would be).
    - The C(brightness) key is null on a router whose LED cannot be dimmed.
  returned: always
  type: dict
  sample: {"led": true, "brightness": 30, "sip_alg": false}
"""

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module


def run(params, client, check_mode):
    led, brightness, sip_alg = params.get("led"), params.get("brightness"), params.get("sip_alg")
    if led is None and brightness is None and sip_alg is None:
        raise ExosModuleError("give at least one of led, brightness, sip_alg")
    if brightness is not None and (brightness % 10 or not 0 <= brightness <= 100):
        raise ExosModuleError("brightness must be 0 to 100 in steps of 10")
    with client:
        before = settings.read_controls(client)
        wanted = dict(before)
        if brightness is not None:
            if before["brightness"] is None:
                raise ExosModuleError("this router's LED cannot be dimmed")
            wanted["brightness"] = brightness
        if led is not None:
            wanted["led"] = bool(led)
        if sip_alg is not None:
            wanted["sip_alg"] = bool(sip_alg)
        if brightness is not None and not wanted["led"]:
            raise ExosModuleError("brightness can only be set while the LED is on")
        if before != wanted and not check_mode:
            if wanted["sip_alg"] != before["sip_alg"]:
                client.call_json("advanced_controls.cmd", {"action": "set", "sip": int(wanted["sip_alg"])})
            if (wanted["led"], wanted["brightness"]) != (before["led"], before["brightness"]):
                payload = {"action": "set", "led": int(wanted["led"])}
                if wanted["led"] and wanted["brightness"] is not None and wanted["brightness"] != before["brightness"]:
                    payload["brightness"] = wanted["brightness"]
                client.call_json("advanced_controls.cmd", payload)
            now = settings.read_controls(client)
            if not wanted["led"]:
                now["brightness"] = wanted["brightness"]   # the router may report any brightness while the LED is off
            if now != wanted:
                raise ExosModuleError("the router accepted the change but reports %s" % now)
    return changed_result(before, wanted, controls=wanted)


def main():
    run_module(dict(led=dict(type="bool"), brightness=dict(type="int"), sip_alg=dict(type="bool")), run)


if __name__ == "__main__":
    main()
