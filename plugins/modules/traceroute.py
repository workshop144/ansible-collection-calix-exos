#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: traceroute
short_description: Trace the route to a host from a Calix EXOS router
version_added: "0.2.0"
description:
  - Runs the router's own traceroute (Utilities > Traceroute in its admin page) and returns the
    hops as the router reports them.
author:
  - Workshop 144 (@workshop144)
options:
  target:
    description:
      - Host name or address to trace.
    type: str
    required: true
  mode:
    description:
      - Kind of probe to send.
    type: str
    choices: [icmp, udp]
    default: icmp
  reverse_dns:
    description:
      - Whether to look up a name for each hop.
    type: bool
    default: false
  ip_version:
    description:
      - Which protocol to use.
    type: str
    choices: [ipv4, ipv6]
    default: ipv4
  wait:
    description:
      - Seconds to wait for the trace to finish. A trace that has not finished is cancelled.
    type: int
    default: 90
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
  - The router runs one traceroute at a time.
"""

EXAMPLES = r"""
- name: Where does traffic to a host go?
  workshop144.calix_exos.traceroute:
    host: 192.0.2.1
    password: "{{ router_password }}"
    target: 198.51.100.7
  register: route
"""

RETURN = r"""
hops:
  description: One entry per hop, in order. C(hop) and C(times) are the router's own text.
  returned: always
  type: list
  elements: dict
  sample: [{"hop": "1  192.0.2.1", "times": ["0.5 ms", "0.4 ms", "0.4 ms"]}]
"""

import time

from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, run_module
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError


def run(params, client, check_mode, sleep=time.sleep):
    target = str(params["target"]).strip()
    if not target or len(target) > 255:
        raise ExosModuleError("target must be a host name or address")
    version = params["ip_version"]
    with client:
        client.call_text("traceroute.cmd", action="trace", ip_addr=target, mode=params["mode"],
                         reverse_dns="enabled" if params["reverse_dns"] else "disabled", version=version)
        reply = None
        for dummy in range(max(1, int(params["wait"]))):
            sleep(1)
            reply = client.call("traceroute.cmd", action="status", version=version)
            if not isinstance(reply, dict) or reply.get("status") != 1:
                break
        else:
            try:
                client.call_text("traceroute.cmd", action="cancel", version=version)
            except ExosError:
                pass
            raise ExosModuleError("the traceroute to %s did not finish within %s seconds" % (target, params["wait"]))
    if not isinstance(reply, dict) or "trace" not in reply:
        raise ExosModuleError("the router did not report a traceroute result for %s: %r" % (target, reply))
    said = " ".join(str(reply[key]) for key in ("msg1", "msg2") if reply.get(key))
    hops = [
        {"hop": row.get("hops"), "times": [row.get(key) for key in ("time1", "time2", "time3") if row.get(key) is not None]}
        for row in reply["trace"] or [] if isinstance(row, dict)
    ]
    if said and not hops:
        raise ExosModuleError("the router could not trace the route to %s: %s" % (target, said))
    return {"changed": False, "hops": hops}


def main():
    run_module(
        dict(
            target=dict(type="str", required=True),
            mode=dict(type="str", default="icmp", choices=["icmp", "udp"]),
            reverse_dns=dict(type="bool", default=False),
            ip_version=dict(type="str", default="ipv4", choices=["ipv4", "ipv6"]),
            wait=dict(type="int", default=90),
        ),
        run,
    )


if __name__ == "__main__":
    main()
