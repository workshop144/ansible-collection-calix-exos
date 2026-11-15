#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: wifi_radio
short_description: Set a Wi-Fi radio of a Calix EXOS router
version_added: "0.2.0"
description:
  - Turns one of the router's radios on or off and sets the options the admin page offers for it
    (Wi-Fi > Radio). Channel, channel width and power are not on that page and are not managed.
  - Only the options given are changed, and only options the radio has can be given. After a
    change the module reads the radios back and fails if the router does not show it.
author:
  - Workshop 144 (@workshop144)
options:
  band:
    description:
      - Which radio.
    type: str
    choices: ["2.4", "5", "6"]
    required: true
  enabled:
    description:
      - Whether the radio is on.
    type: bool
  dfs:
    description:
      - Whether the radio may use DFS channels.
    type: bool
  mu_mimo:
    description:
      - Whether MU-MIMO is on.
    type: bool
  wifi6:
    description:
      - Whether 802.11ax is on.
    type: bool
  wifi7:
    description:
      - Whether 802.11be is on, on a radio that has it.
    type: bool
  wide_channels:
    description:
      - Whether 160 MHz channels are allowed, on a radio that has them.
    type: bool
  psc_only:
    description:
      - Whether a 6 GHz radio uses preferred scanning channels only.
    type: bool
extends_documentation_fragment:
  - workshop144.calix_exos.connection
attributes:
  check_mode:
    support: full
    description: Reports what would change without sending any change to the router.
  diff_mode:
    support: full
    description: Shows the radio before and after.
notes:
  - The router restarts its radios to apply a change. Devices on every band can lose Wi-Fi for
    some seconds. Turning a radio off disconnects every device on it.
  - The router takes all radios in one request, so the module reads them all and sends the
    others back unchanged.
"""

EXAMPLES = r"""
- name: MU-MIMO on for 5 GHz
  workshop144.calix_exos.wifi_radio:
    host: 192.0.2.1
    password: "{{ router_password }}"
    band: "5"
    mu_mimo: true
"""

RETURN = r"""
radio:
  description: The radio after the run (in check mode, as it would be), with the options it has.
  returned: always
  type: dict
  sample: {"band": "5", "enabled": true, "dfs": true, "mu_mimo": true, "psc_only": false, "wifi6": true,
           "wide_channels": false}
"""

import time

from ansible_collections.workshop144.calix_exos.plugins.module_utils import wifi
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module


def run(params, client, check_mode, sleep=time.sleep):
    given = {option: params.get(option) for option in wifi.RADIO_OPTIONS if params.get(option) is not None}
    if not given:
        raise ExosModuleError("give at least one option to set")
    wire_band = wifi.RADIO_BANDS[params["band"]]
    with client:
        raws = [dict(raw) for raw in wifi.radios(client)]
        raw = next((r for r in raws if wifi.radio_band(r) == wire_band), None)
        if raw is None:
            raise ExosModuleError("this router has no %s GHz radio" % params["band"])
        before = wifi.public_radio(raw)
        missing = [option for option in given if option not in before]
        if missing:
            raise ExosModuleError("the %s GHz radio has no setting for %s" % (params["band"], ", ".join(missing)))
        wanted = dict(before, **{option: bool(value) for option, value in given.items()})
        if before != wanted and not check_mode:
            for option, value in given.items():
                raw[wifi.RADIO_OPTIONS[option]] = "1" if value else "0"
            client.call_json("wireless_radiosetup.wl", wifi.radio_payload(raws))
            seen, ok = None, False
            for dummy in range(wifi.SETTLE_TRIES):
                now = next((r for r in wifi.radios(client) if wifi.radio_band(r) == wire_band), None)
                seen = wifi.public_radio(now) if now else None
                if seen == wanted:
                    ok = True
                    break
                sleep(wifi.SETTLE_DELAY)
            if not ok:
                raise ExosModuleError("the router accepted the radio change but reports %r" % (seen,))
    return changed_result(before, wanted, radio=wanted)


def main():
    spec = dict(band=dict(type="str", required=True, choices=["2.4", "5", "6"]))
    spec.update({option: dict(type="bool") for option in wifi.RADIO_OPTIONS})
    run_module(spec, run)


if __name__ == "__main__":
    main()
