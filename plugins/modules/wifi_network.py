#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: wifi_network
short_description: Set the primary Wi-Fi network of a Calix EXOS router
version_added: "0.2.0"
description:
  - Sets the name, security, key and visibility of the router's primary network (Wi-Fi > Primary
    Network in its admin page). The router uses the same settings on every band.
  - Only the options given are changed. After a change the module reads the network back and
    fails if the router does not show what was asked for.
  - B(Changing the name, the security or the key disconnects every device) until each is given
    the new settings. If the control node reaches the router over this Wi-Fi network, the
    module loses the router too and cannot confirm the change.
author:
  - Workshop 144 (@workshop144)
options:
  ssid:
    description:
      - Name of the network, at most 32 characters.
    type: str
  security:
    description:
      - How the network is secured.
    type: str
    choices: [wpa2-wpa3, wpa3, wpa-wpa2, wpa2, enhanced-open, none]
  key:
    description:
      - The Wi-Fi key, 8 to 63 printable ASCII characters.
    type: str
  hidden:
    description:
      - Whether the network hides its name.
    type: bool
extends_documentation_fragment:
  - workshop144.calix_exos.connection
attributes:
  check_mode:
    support: full
    description: Reports what would change without sending any change to the router.
  diff_mode:
    support: full
    description: Shows the setting before and after. A Wi-Fi key is never shown.
notes:
  - The router restarts its radios to apply a Wi-Fi change. Devices on every network of the
    router can lose Wi-Fi for some seconds, and the module waits for the change to show.
  - The key is never returned or logged. The module reads the key the router holds, compares it
    with O(key), and reports only whether it changed.
"""

EXAMPLES = r"""
- name: The house network
  workshop144.calix_exos.wifi_network:
    host: 192.0.2.1
    password: "{{ router_password }}"
    ssid: example
    security: wpa2-wpa3
    key: "{{ wifi_key }}"
"""

RETURN = r"""
network:
  description: The network after the run (in check mode, as it would be). Never the key.
  returned: always
  type: dict
  sample: {"ssid": "example", "security": "wpa2-wpa3", "hidden": false}
key_changed:
  description: Whether the key was, or in check mode would be, changed.
  returned: always
  type: bool
"""

import time

from ansible_collections.workshop144.calix_exos.plugins.module_utils import wifi
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module


def run(params, client, check_mode, sleep=time.sleep):
    if all(params.get(name) is None for name in ("ssid", "security", "key", "hidden")):
        raise ExosModuleError("give at least one of ssid, security, key, hidden")
    new_key = wifi.check_key(params["key"]) if params.get("key") is not None else None
    with client:
        row = wifi.primary_row(client)
        before = wifi.public_primary(row)
        wanted = dict(before)
        if params.get("ssid") is not None:
            wanted["ssid"] = wifi.check_ssid(params["ssid"])
        if params.get("security") is not None:
            wanted["security"] = params["security"]
        if params.get("hidden") is not None:
            wanted["hidden"] = bool(params["hidden"])
        wire_security = wifi.SECURITY.get(wanted["security"], wanted["security"])
        keyless = wire_security in wifi.KEYLESS
        held = wifi.stored_key(row)
        if keyless:
            key = None
        elif new_key is not None:
            key = new_key
        else:
            key = wifi.held_key(row)     # fails if the key the network has cannot be read back cleanly
        key_changed = bool(key) and key != held
        changed = before != wanted or key_changed
        if changed and not check_mode:
            cipher, nonce = wifi.encrypted(client, wanted["ssid"], wire_security, key)
            fields = {"wlSsidIdx": row.get("wlSsidIdx", 1), "wlAuthMode": wire_security, "wlHidden": 1 if wanted["hidden"] else 0,
                      "wlSsidSuffix": 0, "wlSsid": wanted["ssid"], "wlWpaPsk": cipher}
            if nonce:
                fields["nonce"] = nonce
            client.call_text("wireless_multiplessid.wl", **fields)
            seen, ok = None, False
            for dummy in range(wifi.SETTLE_TRIES):
                now = wifi.primary_row(client)
                seen = wifi.public_primary(now)
                if seen == wanted and (keyless or wifi.stored_key(now) == key):
                    ok = True
                    break
                sleep(wifi.SETTLE_DELAY)
            if not ok:
                raise ExosModuleError("the router accepted the Wi-Fi change but reports %s" % seen)
    result = changed_result(before, wanted, network=wanted, key_changed=key_changed)
    result["changed"] = changed
    return result


def main():
    run_module(
        dict(
            ssid=dict(type="str"),
            security=dict(type="str", choices=list(wifi.SECURITY)),
            key=dict(type="str", no_log=True),
            hidden=dict(type="bool"),
        ),
        run,
    )


if __name__ == "__main__":
    main()
