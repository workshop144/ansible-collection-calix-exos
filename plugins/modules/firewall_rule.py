#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: firewall_rule
short_description: Manage one custom firewall rule on a Calix EXOS router
version_added: "0.2.0"
description:
  - Adds, changes or removes a rule on Advanced > Security > Advanced Firewall in the router's
    admin page. Rules are held in four chains (IPv4 and IPv6, traffic in and traffic out) and
    are matched in order; the first match wins.
  - A rule is identified by its name within its chain. A new rule goes at the end of the chain; a
    changed rule keeps its place.
  - The router takes a whole chain at a time, so the module reads the chain, changes the one
    rule and writes the chain back, then reads it again to confirm.
author:
  - Workshop 144 (@workshop144)
options:
  chain:
    description:
      - Which chain the rule is in.
    type: str
    choices: [ipv4_in, ipv4_out, ipv6_in, ipv6_out]
    required: true
  name:
    description:
      - Name of the rule, at most 32 characters, without spaces, quotes, C(<), C(>) or C(&).
    type: str
    required: true
  source:
    description:
      - Source address or network (for example V(192.0.2.0/24)). Any source when not given.
    type: str
  destination:
    description:
      - Destination address or network. Any destination when not given.
    type: str
  protocol:
    description:
      - Protocol to match.
    type: str
    choices: [tcp, udp, both]
    default: tcp
  source_port:
    description:
      - Source port, or a range written V(start:end). Any port when not given.
    type: str
  destination_port:
    description:
      - Destination port, or a range written V(start:end). Any port when not given.
    type: str
  action:
    description:
      - What to do with matching traffic.
    type: str
    choices: [accept, drop]
    default: drop
  state:
    description:
      - Whether the rule should exist.
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
  - A chain holds at most 64 rules.
"""

EXAMPLES = r"""
- name: Devices on the LAN may not reach one outside address over telnet
  workshop144.calix_exos.firewall_rule:
    host: 192.0.2.1
    password: "{{ router_password }}"
    chain: ipv4_out
    name: no-telnet-there
    destination: 198.51.100.7
    protocol: tcp
    destination_port: "23"
    action: drop
"""

RETURN = r"""
rule:
  description: The rule after the run (in check mode, as it would be), or null.
  returned: always
  type: dict
  sample: {"chain": "ipv4_out", "name": "no-telnet-there", "source": null, "destination": "198.51.100.7",
           "protocol": "tcp", "source_port": null, "destination_port": "23", "action": "drop"}
"""

import ipaddress
import re

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, changed_result, run_module

MAX_RULES = 64


def _network(value, chain, what):
    if not value:
        return ""
    text = str(value).strip()
    try:
        parsed = ipaddress.ip_network(text, strict=False) if "/" in text else ipaddress.ip_address(text)
    except ValueError:
        raise ExosModuleError("%s is not an address or network: %r" % (what, value)) from None
    if parsed.version != (4 if "ipv4" in chain else 6):
        raise ExosModuleError("%s must be an IPv%s address for chain %s" % (what, 4 if "ipv4" in chain else 6, chain))
    return text


def _ports(value, what):
    if value in (None, ""):
        return ""
    text = str(value).strip()
    parts = text.split(":")
    if len(parts) > 2 or not all(part.isdigit() and int(part) <= 65535 for part in parts):
        raise ExosModuleError("%s must be a port (0-65535) or a range start:end, not %r" % (what, value))
    if len(parts) == 2 and int(parts[0]) > int(parts[1]):
        raise ExosModuleError("%s: the range starts above its end" % what)
    return text


def _wire(params):
    name = str(params["name"])
    if not name or len(name) > 32 or not re.fullmatch(r"[^ ><'\x22&]*", name):
        raise ExosModuleError("not a rule name the router accepts: %r" % (params["name"],))
    chain = params["chain"]
    return {
        "name": name,
        "srcip": _network(params.get("source"), chain, "source"),
        "dstip": _network(params.get("destination"), chain, "destination"),
        "proto": settings.RULE_PROTOCOLS[params["protocol"]],
        "sport": _ports(params.get("source_port"), "source_port"),
        "dport": _ports(params.get("destination_port"), "destination_port"),
        "action": params["action"].upper(),
    }


def _index(rules, name):
    return next((i for i, rule in enumerate(rules) if rule.get("name") == name), None)


def run(params, client, check_mode):
    chain = params["chain"]
    present = params["state"] == "present"
    wire = _wire(params) if present else {"name": str(params["name"])}
    with client:
        rules = settings.read_chain(client, chain)
        at = _index(rules, wire["name"])
        before = settings.public_firewall_rule(chain, rules[at]) if at is not None else None
        new_rules = [dict(rule) for rule in rules]
        if present:
            if at is None:
                if len(rules) >= MAX_RULES:
                    raise ExosModuleError("the %s chain already holds %d rules, the most the router takes" % (chain, MAX_RULES))
                new_rules.append(wire)
            else:
                new_rules[at] = dict(rules[at], **wire)
        elif at is not None:
            del new_rules[at]
        new_at = _index(new_rules, wire["name"])
        after = settings.public_firewall_rule(chain, new_rules[new_at]) if new_at is not None else None
        if before != after and not check_mode:
            client.call_json("advfw_apply.cmd", {settings.CHAINS[chain]: new_rules})
            now_rules = settings.read_chain(client, chain)
            now_at = _index(now_rules, wire["name"])
            now = settings.public_firewall_rule(chain, now_rules[now_at]) if now_at is not None else None
            if now != after:
                raise ExosModuleError("the router accepted the firewall rule change but reports %r for %s" % (now, wire["name"]))
    return changed_result(before, after, rule=after)


def main():
    run_module(
        dict(
            chain=dict(type="str", required=True, choices=["ipv4_in", "ipv4_out", "ipv6_in", "ipv6_out"]),
            name=dict(type="str", required=True),
            source=dict(type="str"),
            destination=dict(type="str"),
            protocol=dict(type="str", default="tcp", choices=["tcp", "udp", "both"]),
            source_port=dict(type="str"),
            destination_port=dict(type="str"),
            action=dict(type="str", default="drop", choices=["accept", "drop"]),
            state=dict(type="str", default="present", choices=["present", "absent"]),
        ),
        run,
    )


if __name__ == "__main__":
    main()
