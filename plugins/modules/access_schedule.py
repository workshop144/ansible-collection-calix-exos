#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: access_schedule
short_description: Block a device's internet access at set times on a Calix EXOS router
version_added: "0.2.0"
description:
  - Manages one entry of Advanced > Parental Control > Scheduling Access in the router's admin
    page. An entry cuts one device off from the internet on the given days between two times of
    day, or always when no days are given.
  - An entry is identified by the device, the days and the times together.
  - After a change the module reads the list back and fails if the router does not show what was
    asked for.
author:
  - Workshop 144 (@workshop144)
options:
  mac:
    description:
      - MAC address of the device. Any common notation is accepted.
    type: str
    required: true
  days:
    description:
      - Days on which to block. Leave out, with O(start) and O(end), to block the device always.
    type: list
    elements: str
    choices: [mon, tue, wed, thu, fri, sat, sun]
  start:
    description:
      - Time of day the block starts, as V(HH:MM) on a 24-hour clock. Required with O(days).
    type: str
  end:
    description:
      - Time of day the block ends. It must be later than O(start). Required with O(days).
    type: str
  state:
    description:
      - Whether the entry should exist.
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
notes:
  - The router refuses changes to parental controls while the provider's app manages them. The
    module then fails without changing anything.
"""

EXAMPLES = r"""
- name: No internet for the console on school nights
  workshop144.calix_exos.access_schedule:
    host: 192.0.2.1
    password: "{{ router_password }}"
    mac: "02:00:00:00:00:aa"
    days: [sun, mon, tue, wed, thu]
    start: "21:00"
    end: "23:59"
"""

RETURN = r"""
schedule:
  description: The entry after the run (in check mode, as it would be), or null.
  returned: always
  type: dict
  sample: {"mac": "02:00:00:00:00:aa", "days": ["mon", "tue"], "start": "21:00", "end": "23:59"}
"""

import re
import time

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import normalize_mac

WIRE_DAYS = dict(zip(settings.DAYS, ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")))


def _clock(value, what):
    text = str(value).strip()
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", text):
        raise ExosModuleError("%s must be a time of day written HH:MM, not %r" % (what, value))
    return text


def _wanted(params):
    try:
        mac = normalize_mac(params["mac"])
    except ValueError as err:
        raise ExosModuleError(str(err)) from None
    days, start, end = params.get("days"), params.get("start"), params.get("end")
    if not days and start is None and end is None:
        return {"mac": mac, "days": [], "start": None, "end": None}
    if not days or start is None or end is None:
        raise ExosModuleError("give days, start and end together, or none of them to block the device always")
    unknown = [day for day in days if str(day).lower() not in settings.DAYS]
    if unknown:
        raise ExosModuleError("not a day: %s" % ", ".join(str(day) for day in unknown))
    start, end = _clock(start, "start"), _clock(end, "end")
    if start >= end:
        raise ExosModuleError("start must be earlier than end")
    return {"mac": mac, "days": sorted({str(day).lower() for day in days}, key=settings.DAYS.index), "start": start, "end": end}


def _find(entries, wanted):
    for entry in entries:
        if {key: entry[key] for key in wanted} == wanted:
            return entry
    return None


def run(params, client, check_mode):
    wanted = _wanted(params)
    present = params["state"] == "present"
    with client:
        found = _find(settings.read_access_schedules(client), wanted)
        before = dict(wanted) if found else None
        after = dict(wanted) if present else None
        if before != after:
            settings.require_local_parental_controls(client)
        if before != after and not check_mode:
            if present:
                payload = {"action": "add", "mac": wanted["mac"], "username": str(int(time.time() * 1000))}
                if wanted["days"]:
                    payload.update(days=",".join(WIRE_DAYS[day] for day in wanted["days"]),
                                   start_time=wanted["start"], end_time=wanted["end"])
                client.call_json("detail_access.cmd", payload)
            else:
                client.call_json("detail_access.cmd", {"action": "remove", "username": found["_id"]})
            now = dict(wanted) if _find(settings.read_access_schedules(client), wanted) else None
            if now != after:
                raise ExosModuleError("the router accepted the schedule change but does not show it")
    return changed_result(before, after, schedule=after)


def main():
    run_module(
        dict(
            mac=dict(type="str", required=True),
            days=dict(type="list", elements="str", choices=list(settings.DAYS)),
            start=dict(type="str"),
            end=dict(type="str"),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        ),
        run,
        required_together=[("days", "start", "end")],
    )


if __name__ == "__main__":
    main()
