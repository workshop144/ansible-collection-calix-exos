#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: wifi_secondary_network
short_description: Manage a guest or other secondary Wi-Fi network on a Calix EXOS router
version_added: "0.2.0"
description:
  - Creates, changes or removes one secondary network (Wi-Fi > Secondary Networks in the
    router's admin page). The primary network is managed with M(workshop144.calix_exos.wifi_network).
  - A network is identified by its name. Its kind and band are fixed when it is created.
  - After a change the module reads the networks back and fails if the router does not show what
    was asked for.
author:
  - Workshop 144 (@workshop144)
options:
  ssid:
    description:
      - Name of the network, at most 32 characters.
    type: str
    required: true
  kind:
    description:
      - What sort of network to create; V(guest) when not given. V(guest) and V(work_from_home)
        use every band.
      - It cannot be changed afterwards. For a network that exists, leave it out or give the
        kind it has.
    type: str
    choices: [guest, work_from_home, custom]
  band:
    description:
      - Band of a V(custom) network; every band when not given. It cannot be changed afterwards.
    type: str
    choices: ["2.4", "5", "6", all]
  security:
    description:
      - How the network is secured. A new network gets V(wpa2-wpa3) when this is not given; a
        network that exists keeps what it has.
      - A 6 GHz network takes V(wpa3) or V(enhanced-open) only, and a V(work_from_home) network
        cannot be V(none).
    type: str
    choices: [wpa2-wpa3, wpa3, wpa-wpa2, wpa2, enhanced-open, none]
  key:
    description:
      - The Wi-Fi key, 8 to 63 printable ASCII characters. Required to create a secured network.
      - When not given for a network that exists, the key it has is kept.
    type: str
  isolation:
    description:
      - Whether the network gets its own subnet, apart from the main LAN. The router's default is
        on for V(guest) and V(work_from_home) networks.
    type: bool
  state:
    description:
      - Whether the network should exist.
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
    description: Shows the setting before and after. A Wi-Fi key is never shown.
notes:
  - The router restarts its radios to apply a Wi-Fi change. Devices on every network of the
    router can lose Wi-Fi for some seconds, and the module waits for the change to show.
  - The key is never returned or logged. The module reads the key the router holds, compares it
    with O(key), and reports only whether it changed.
"""

EXAMPLES = r"""
- name: A guest network
  workshop144.calix_exos.wifi_secondary_network:
    host: 192.0.2.1
    password: "{{ router_password }}"
    ssid: guests
    key: "{{ guest_wifi_key }}"
"""

RETURN = r"""
network:
  description: The network after the run (in check mode, as it would be), or null. Never the key.
  returned: always
  type: dict
  sample: {"ssid": "guests", "kind": "guest", "band": "all", "security": "wpa2-wpa3", "isolation": true}
key_changed:
  description: Whether the key was, or in check mode would be, changed.
  returned: always
  type: bool
"""

import time

from ansible_collections.workshop144.calix_exos.plugins.module_utils import wifi
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module

ENDPOINT = "wireless_multiplessid.wl"


def _find(rows, ssid):
    return next((row for row in rows if row.get("wlSsid") == ssid), None)


def _settled(client, ssid, expect, key, sleep):
    """Wait for the network to look as expected; returns the last state seen."""
    seen = None
    for dummy in range(wifi.SETTLE_TRIES):
        row = _find(wifi.secondary_rows(client), ssid)
        seen = wifi.public_secondary(row) if row else None
        if seen == expect and (expect is None or not key or wifi.stored_key(row) == key):
            return seen, True
        sleep(wifi.SETTLE_DELAY)
    return seen, False


def run(params, client, check_mode, sleep=time.sleep):
    ssid = wifi.check_ssid(params["ssid"])
    present = params["state"] == "present"
    given_key = wifi.check_key(params["key"]) if present and params.get("key") is not None else None
    with client:
        row = _find(wifi.secondary_rows(client), ssid)
        before = wifi.public_secondary(row) if row else None
        key, key_changed, after, wire_security = None, False, None, None
        if present:
            if row is None:
                kind = params.get("kind") or "guest"
                band = (params.get("band") or "all") if kind == "custom" else "all"
                security = params.get("security") or "wpa2-wpa3"
                isolation = params["isolation"] if params.get("isolation") is not None else kind in ("guest", "work_from_home")
            else:
                kind, band = before["kind"], before["band"]
                if params.get("kind") is not None and params["kind"] != kind:
                    raise ExosModuleError("%s is a %s network; its kind cannot be changed, remove it first" % (ssid, kind))
                if params.get("band") is not None and kind == "custom" and params["band"] != band:
                    raise ExosModuleError("%s is on band %s; its band cannot be changed, remove it first" % (ssid, band))
                security = params.get("security") or before["security"]
                isolation = params["isolation"] if params.get("isolation") is not None else before["isolation"]
            wire_security = wifi.SECURITY.get(security, security)
            keyless = wire_security in wifi.KEYLESS
            if band == "6" and wire_security not in ("wpa3", "owe"):
                raise ExosModuleError("a 6 GHz network takes security wpa3 or enhanced-open only")
            if kind == "work_from_home" and wire_security == "disabled":
                raise ExosModuleError("a work_from_home network cannot be open")
            after = {"ssid": ssid, "kind": kind, "band": band, "security": security, "isolation": isolation}
            if not keyless:
                held = wifi.stored_key(row) if row else ""
                if given_key is not None:
                    key = given_key
                elif row is None:
                    raise ExosModuleError("a key is required to create a secured network")
                elif before == after:
                    key = held                      # nothing to send, so nothing to read back cleanly
                else:
                    key = wifi.held_key(row)        # fails if the key it has cannot be read back cleanly
                key_changed = key != held
        changed = before != after or key_changed
        if changed and not check_mode:
            if after is None:
                payload = dict(row, actiondo=0, wlSubnet=1 if before["isolation"] else 0,
                               smart_qos=1 if wifi.flag(row.get("smart_qos", 0)) else 0)
                payload.pop("wlWpaPsk", None)
            else:
                cipher, nonce = wifi.encrypted(client, ssid, wire_security, key)
                if row is None:
                    pool = wifi.pool_status(client)
                    slot = wifi.POOL_KEYS[wifi.BANDS[after["band"]] if after["kind"] == "custom" else "unified"]
                    if int(pool.get(slot, 0) or 0) < 1:
                        raise ExosModuleError("the router cannot hold another network of this kind")
                    network_type = "custom_%s" % wifi.BANDS[after["band"]] if after["kind"] == "custom" else wifi.KINDS[after["kind"]]
                    payload = {"smart_qos": 0, "wlSsid": ssid, "wlEnbl": 1, "wlAuthMode": wire_security, "wlWpaPsk": cipher,
                               "nonce": nonce or "", "wlSubnet": 1 if after["isolation"] else 0, "wlEnblTime": "",
                               "wlDisblTime": "", "oldname": "", "actiondo": 1, "networkType": network_type}
                    subnet = pool.get(slot + "IP")
                    if subnet:
                        payload.update(wlStartIp="192.168.%s.2" % subnet, wlEndIp="192.168.%s.254" % subnet,
                                       wlGateway="192.168.%s.1" % subnet, wlMask="255.255.255.0")
                else:
                    payload = dict(row, actiondo=2, oldname=ssid, wlEnbl=1, wlAuthMode=wire_security, wlWpaPsk=cipher,
                                   nonce=nonce or "", wlSubnet=1 if after["isolation"] else 0,
                                   smart_qos=1 if wifi.flag(row.get("smart_qos", 0)) else 0)
            client.call_text(ENDPOINT, **payload)
            seen, ok = _settled(client, ssid, after, key, sleep)
            if not ok:
                raise ExosModuleError("the router accepted the change to %s but reports %r for it" % (ssid, seen))
    result = changed_result(before, after, network=after, key_changed=key_changed)
    result["changed"] = changed
    return result


def main():
    run_module(
        dict(
            ssid=dict(type="str", required=True),
            kind=dict(type="str", choices=["guest", "work_from_home", "custom"]),
            band=dict(type="str", choices=["2.4", "5", "6", "all"]),
            security=dict(type="str", choices=list(wifi.SECURITY)),
            key=dict(type="str", no_log=True),
            isolation=dict(type="bool"),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        ),
        run,
    )


if __name__ == "__main__":
    main()
