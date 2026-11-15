#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: ping
short_description: Ping a host from a Calix EXOS router
version_added: "0.2.0"
description:
  - Runs the router's own ping test (Utilities > Ping Test in its admin page) and returns the
    result, so that reachability can be checked from the router's point of view.
  - The task does not fail when the host does not answer; see RV(reachable).
author:
  - Workshop 144 (@workshop144)
options:
  target:
    description:
      - Host name or address to ping.
    type: str
    required: true
  packet_size:
    description:
      - Size of each packet in bytes.
    type: int
    default: 32
  source_ip:
    description:
      - Address of the router to ping from. The router chooses when not given.
    type: str
  ip_version:
    description:
      - Which protocol to use.
    type: str
    choices: [ipv4, ipv6]
    default: ipv4
  wait:
    description:
      - Seconds to wait for the test to finish.
    type: int
    default: 30
extends_documentation_fragment:
  - workshop144.calix_exos.connection
attributes:
  check_mode:
    support: full
    description: The test changes nothing on the router, so it runs in check mode too.
  diff_mode:
    support: none
    description: Nothing is changed, so there is nothing to diff.
notes:
  - The router runs one ping test at a time.
"""

EXAMPLES = r"""
- name: Can the router reach the internet?
  workshop144.calix_exos.ping:
    host: 192.0.2.1
    password: "{{ router_password }}"
    target: one.one.one.one
  register: outside
  failed_when: not outside.reachable
"""

RETURN = r"""
reachable:
  description: Whether at least one reply came back.
  returned: always
  type: bool
ping:
  description: Counts, timings in milliseconds (null when there was no reply) and each reply.
  returned: always
  type: dict
  sample: {"target": "192.0.2.9", "sent": 4, "received": 4, "loss_percent": 0.0, "min_ms": 0.9, "max_ms": 1.2,
           "avg_ms": 1.0, "replies": [{"from": "192.0.2.9", "bytes": 40, "time_ms": 1.2, "ttl": 64}]}
"""

import re
import time

from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, run_module


def _number(value, kind=float):
    match = re.search(r"-?\d+(\.\d+)?", str(value))
    return kind(float(match.group(0))) if match else None


def run(params, client, check_mode, sleep=time.sleep):
    target = str(params["target"]).strip()
    if not target or len(target) > 255:
        raise ExosModuleError("target must be a host name or address")
    if not 1 <= int(params["packet_size"]) <= 65507:
        raise ExosModuleError("packet_size must be between 1 and 65507")
    version = params["ip_version"]
    with client:
        client.call_text("ping_test.cmd", action="start_ping", version=version, ip_addr=target,
                         packet_size=params["packet_size"], source_ip=params.get("source_ip") or "")
        reply = None
        for dummy in range(max(1, int(params["wait"]))):
            sleep(1)
            reply = client.call("ping_test.cmd", action="status", version="ipv4")
            if not isinstance(reply, dict) or reply.get("status") != 1:
                break
        else:
            raise ExosModuleError("the ping test to %s did not finish within %s seconds" % (target, params["wait"]))
    if not isinstance(reply, dict) or "status" not in reply:
        raise ExosModuleError("the router did not report a ping result for %s: %r" % (target, reply))
    if reply.get("msg"):
        raise ExosModuleError("the router could not ping %s: %s" % (target, reply["msg"]))
    stats = reply.get("statistic") if isinstance(reply.get("statistic"), dict) else {}
    replies = [
        {"from": row.get("from"), "bytes": _number(row.get("bytes"), int), "time_ms": _number(row.get("time")),
         "ttl": _number(row.get("ttl"), int)}
        for row in reply.get("result") or [] if isinstance(row, dict)
    ]
    received = _number(stats.get("receive"), int) or 0
    result = {
        "target": target,
        "sent": _number(stats.get("sent"), int) or 0,
        "received": received,
        "loss_percent": _number(stats.get("loss")),
        "min_ms": _number(stats.get("min")),
        "max_ms": _number(stats.get("max")),
        "avg_ms": _number(stats.get("avg")),
        "replies": replies,
    }
    return {"changed": False, "reachable": received > 0, "ping": result}


def main():
    run_module(
        dict(
            target=dict(type="str", required=True),
            packet_size=dict(type="int", default=32),
            source_ip=dict(type="str"),
            ip_version=dict(type="str", default="ipv4", choices=["ipv4", "ipv6"]),
            wait=dict(type="int", default=30),
        ),
        run,
    )


if __name__ == "__main__":
    main()
