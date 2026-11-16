#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: device
short_description: Name a device the Calix EXOS router knows about
version_added: "0.2.0"
description:
  - Sets the name and the kind of a device in the router's device list (Status > Devices in its
    admin page). The device must already be known to the router.
  - Only the options given are changed. After a change the module reads the list back and fails
    if the router does not show it.
author:
  - Workshop 144 (@workshop144)
options:
  mac:
    description:
      - MAC address of the device. Any common notation is accepted.
    type: str
    required: true
  name:
    description:
      - Name to show for the device, at most 63 characters.
    type: str
  type:
    description:
      - What kind of device it is.
    type: str
    choices: [Computer, Ebook, Tablet, Game Console, IP Camera, Media Player, Mobile, Smart Phone, Network,
              Printer, TV, VoIP, IoT Hub, Doorbell]
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
- name: Call the printer what it is
  workshop144.calix_exos.device:
    host: 192.0.2.1
    password: "{{ router_password }}"
    mac: "02:00:00:00:00:aa"
    name: office printer
    type: Printer
"""

RETURN = r"""
device:
  description: The device after the run (in check mode, as it would be).
  returned: always
  type: dict
  sample: {"mac": "02:00:00:00:00:aa", "name": "office printer", "type": "Printer"}
"""

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import normalize_mac

TYPES = ["Computer", "Ebook", "Tablet", "Game Console", "IP Camera", "Media Player", "Mobile", "Smart Phone", "Network",
         "Printer", "TV", "VoIP", "IoT Hub", "Doorbell"]


def _find(client, mac):
    for row in settings.read_devices(client):
        try:
            if normalize_mac(row.get("macAddress")) == mac:
                return row
        except ValueError:
            continue
    return None


def _public(row, mac):
    return {"mac": mac, "name": row.get("deviceName"), "type": row.get("type") or None}


def run(params, client, check_mode):
    try:
        mac = normalize_mac(params["mac"])
    except ValueError as err:
        raise ExosModuleError(str(err)) from None
    name, kind = params.get("name"), params.get("type")
    if name is None and kind is None:
        raise ExosModuleError("give at least one of name, type")
    if name is not None and not 0 < len(name) <= 63:
        raise ExosModuleError("name must be 1 to 63 characters")
    with client:
        row = _find(client, mac)
        if row is None:
            raise ExosModuleError("the router does not know a device with MAC %s" % mac)
        before = _public(row, mac)
        wanted = dict(before)
        if name is not None:
            wanted["name"] = name
        if kind is not None:
            wanted["type"] = kind
        if before != wanted and not check_mode:
            client.call_text("device_table.cmd", action="set", version="ipv4", mac=row["macAddress"],
                             type=wanted["type"], deviceName=wanted["name"])
            again = _find(client, mac)
            now = _public(again, mac) if again else None
            if now != wanted:
                raise ExosModuleError("the router accepted the device change but reports %r" % (now,))
    return changed_result(before, wanted, device=wanted)


def main():
    run_module(dict(mac=dict(type="str", required=True), name=dict(type="str"), type=dict(type="str", choices=TYPES)), run)


if __name__ == "__main__":
    main()
