#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: dhcp_reservation
short_description: Manage one DHCP reservation on a Calix EXOS router
version_added: "0.1.0"
description:
  - Adds or removes a DHCP reservation (a fixed address for one MAC address) on a Calix EXOS
    router (the GigaSpire family), through the router's local web interface.
  - A reservation is identified by its MAC address. Asking for a different address for a MAC that
    already has one removes the old reservation and adds the new one.
  - After every change the module reads the table back and fails if the router does not show
    what was asked for.
author:
  - Workshop 144 (@workshop144)
options:
  mac:
    description:
      - MAC address of the device. Any common notation is accepted.
    type: str
    required: true
  ip:
    description:
      - Address to reserve. Required when O(state=present).
      - The module fails, without changing anything, if another MAC already holds this address.
    type: str
  pool:
    description:
      - Name of the DHCP pool, as the router calls it. The primary LAN is V(lan).
    type: str
    default: lan
  state:
    description:
      - Whether the reservation should exist.
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
    description: Shows the reservation for this MAC before and after.
notes:
  - If the old reservation was removed and the new one could not be added, the module tries once
    to put the old one back, then fails and says which reservation is on the router now.
  - The router applies a reservation the next time the device asks for an address.
"""

EXAMPLES = r"""
- name: Reserve an address for the printer
  workshop144.calix_exos.dhcp_reservation:
    host: 192.0.2.1
    password: "{{ router_password }}"
    mac: "02:00:00:00:00:aa"
    ip: 192.0.2.150

- name: Remove a reservation
  workshop144.calix_exos.dhcp_reservation:
    host: 192.0.2.1
    password: "{{ router_password }}"
    mac: "02:00:00:00:00:aa"
    state: absent
"""

RETURN = r"""
reservation:
  description: The reservation for this MAC after the run (in check mode, as it would be), or null.
  returned: always
  type: dict
  sample: {"pool": "lan", "mac": "02:00:00:00:00:aa", "ip": "192.0.2.150"}
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.workshop144.calix_exos.plugins.module_utils import normalize
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import (
    EXOS_ARGUMENT_SPEC,
    ExosError,
    client_from_module,
    normalize_mac,
)

ENDPOINT = "dhcpdstaticlease.cmd"


class ReservationError(Exception):
    """The request cannot be met, or the router did not end up as asked."""


def _for_mac(entries, mac):
    return next((entry for entry in entries if entry["mac"] == mac), None)


def decide(current, mac, ip, pool, state):
    """Return what to do: ``none``, ``add``, ``remove`` or ``replace``."""
    existing = _for_mac(current, mac)
    if state == "absent":
        return "remove" if existing else "none"
    holder = next((entry for entry in current if entry["ip"] == ip and entry["mac"] != mac), None)
    if holder:
        raise ReservationError("%s is already reserved for %s" % (ip, holder["mac"]))
    if existing is None:
        return "add"
    if existing["ip"] == ip and existing["pool"] == pool:
        return "none"
    return "replace"


def _read(client):
    return normalize.reservations(client.call("dhcp_reservation.cmd", action="init"))


def _add(client, entry):
    client.call(ENDPOINT, action="add", dhcpPool=entry["pool"], mac=entry["mac"], static_ip=entry["ip"])
    if _for_mac(_read(client), entry["mac"]) != entry:
        raise ReservationError(
            "the router accepted a reservation of %s for %s but does not list it" % (entry["ip"], entry["mac"])
        )


def _remove(client, entry):
    client.call(ENDPOINT, action="remove", rmLst=entry["ip"])
    if _for_mac(_read(client), entry["mac"]) is not None:
        raise ReservationError(
            "the router accepted the removal of %s for %s but still lists it" % (entry["ip"], entry["mac"])
        )


def _replace(client, old, new):
    _remove(client, old)
    try:
        _add(client, new)
    except (ExosError, ReservationError) as err:
        try:
            _add(client, old)
        except (ExosError, ReservationError):
            raise ReservationError(
                "could not reserve %s for %s (%s), and the old reservation of %s could not be put back: "
                "there is now no reservation for %s on the router" % (new["ip"], new["mac"], err, old["ip"], new["mac"])
            ) from None
        raise ReservationError(
            "could not reserve %s for %s (%s); the old reservation of %s was restored"
            % (new["ip"], new["mac"], err, old["ip"])
        ) from None


def run(params, client, check_mode):
    """Log in, bring the one reservation to the requested state, log out."""
    try:
        mac = normalize_mac(params["mac"])
    except ValueError as err:
        raise ReservationError(str(err)) from None
    state = params["state"]
    wanted = {"pool": params["pool"], "mac": mac, "ip": params["ip"]} if state == "present" else None

    with client:
        current = _read(client)
        before = _for_mac(current, mac)
        action = decide(current, mac, params["ip"], params["pool"], state)
        if action != "none" and not check_mode:
            if action == "add":
                _add(client, wanted)
            elif action == "remove":
                _remove(client, before)
            else:
                _replace(client, before, wanted)

    after = before if action == "none" else wanted
    return {"changed": action != "none", "reservation": after, "diff": {"before": before, "after": after}}


def main():
    argument_spec = dict(EXOS_ARGUMENT_SPEC)
    argument_spec.update(
        mac=dict(type="str", required=True),
        ip=dict(type="str"),
        pool=dict(type="str", default="lan"),
        state=dict(type="str", default="present", choices=["present", "absent"]),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[("state", "present", ("ip",))],
        supports_check_mode=True,
    )
    try:
        result = run(module.params, client_from_module(module), module.check_mode)
    except ExosError as err:
        module.fail_json(msg=str(err), code=err.code, endpoint=err.endpoint)
    except ReservationError as err:
        module.fail_json(msg=str(err))
    module.exit_json(**result)


if __name__ == "__main__":
    main()
