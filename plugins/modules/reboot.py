#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: reboot
short_description: Restart a Calix EXOS router
version_added: "0.3.0"
description:
  - Restarts the router (Utilities > Reboot in its admin page) and, by default, waits until it
    answers again.
  - B(Everything behind the router is offline while it restarts), usually for a few minutes.
    If the control node reaches the router through the router's own internet connection, the
    wait simply lasts until that path is back.
author:
  - Workshop 144 (@workshop144)
options:
  wait:
    description:
      - Whether to wait for the router to answer again before the task ends.
    type: bool
    default: true
  timeout:
    description:
      - Seconds to wait, in all, before the task fails.
    type: int
    default: 600
  settle:
    description:
      - Seconds to wait before first asking whether the router is back. The admin page waits 80.
    type: int
    default: 80
extends_documentation_fragment:
  - workshop144.calix_exos.connection
attributes:
  check_mode:
    support: full
    description: Logs in to show the router is reachable, reports a change, and does not restart it.
  diff_mode:
    support: none
    description: There is nothing to diff.
"""

EXAMPLES = r"""
- name: Restart the router and carry on when it is back
  workshop144.calix_exos.reboot:
    host: 192.0.2.1
    password: "{{ router_password }}"
"""

RETURN = r"""
rebooted:
  description: Whether the restart was requested. False in check mode.
  returned: always
  type: bool
waited_seconds:
  description: How long the module waited for the router to answer again. 0 without O(wait).
  returned: always
  type: int
"""

import time

from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, run_module
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError

POLL = 5


def _answers(client):
    try:
        return bool(client.call_text("login_nonce.cmd"))
    except ExosError:
        return False


def run(params, client, check_mode, sleep=time.sleep):
    client.login()
    if check_mode:
        client.logout()
        return {"changed": True, "rebooted": False, "waited_seconds": 0}
    try:
        client.call_text("rebootinfo.cgi")
    except ExosError as err:
        if err.code is not None or "no session" in str(err):
            raise
        # the router can drop the connection as it goes down: that is the restart starting
    waited = 0
    if params["wait"]:
        sleep(params["settle"])
        waited = params["settle"]
        while not _answers(client):
            if waited >= params["timeout"]:
                raise ExosModuleError("the router did not answer again within %d seconds of the restart" % params["timeout"])
            sleep(POLL)
            waited += POLL
    return {"changed": True, "rebooted": True, "waited_seconds": waited}


def main():
    run_module(
        dict(wait=dict(type="bool", default=True), timeout=dict(type="int", default=600), settle=dict(type="int", default=80)),
        run,
    )


if __name__ == "__main__":
    main()
