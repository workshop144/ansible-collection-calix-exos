# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Handlers that make FakeRouter behave like the router's settings pages. Values are made up."""

from __future__ import annotations

from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosClient
from ansible_collections.workshop144.calix_exos.tests.unit.fakes import FakeRouter

READ_ACTIONS = ("get", "readall", "loadTableData", "init", "load", "get_status", "status", "getStatus",
                "get_radio_setup", "get_ssid_setup", "get_pool_status", "check")
SESSION = ("login_nonce.cmd", "login.cgi", "logout.cgi", "get_access_status.cmd", "get_nonce.cmd")


def writes(router):
    """Every request that was not a read or part of the session."""
    out = []
    for endpoint, params in router.calls:
        action = params.get("action") if isinstance(params, dict) else None
        if endpoint in SESSION or endpoint in router.state.get("read_endpoints", ()):
            continue
        if action in READ_ACTIONS:
            continue
        out.append((endpoint, params))
    return out


def _params(router, action, params):
    wanted = [n for field in ("ejGetVal", "ejGetOtherVal") for n in params.get(field, "").split(",") if n]
    store = dict(router.state["params"])
    dmz = router.state["dmz"]
    store["dmzHost"] = "1|%s" % dmz if dmz else "0|"
    return {name: store[name] for name in wanted if name in store}


def _upnp(router, action, params):
    if not router.drop_writes:
        router.state["params"]["enblUpnp"] = str(params["enblUpnp"])
        router.state["params"]["enblUpnpnat"] = str(params["enblUpnpnat"])
    return ""


def _dmz(router, action, params):
    if action == "add":
        if router.state["dmz"]:
            return "#ERROR_510"
        if not router.drop_writes:
            router.state["dmz"] = params["address"]
    elif action == "remove" and not router.drop_writes and router.state["dmz"] == params["address"]:
        router.state["dmz"] = None
    return ""


FORWARD_FIELDS = ("protocol", "localIpAddress", "localPortStart", "localPortEnd",
                  "remoteIpAddress", "remotePortStart", "remotePortEnd")


def _forward_list(router, action, params):
    return "|".join(",".join(rule) for rule in router.state["forwards"])


def _forward(router, action, params):
    rule = [params[field] for field in FORWARD_FIELDS]
    if rule[4] == "":
        rule[4] = "0.0.0.0"
    if router.drop_writes:
        return ""
    if action == "add":
        router.state["forwards"].append(rule)
    elif action == "remove":
        router.state["forwards"] = [r for r in router.state["forwards"] if r != rule]
    return ""


def _dns(router, action, params):
    table = router.state["dns"]
    if action == "loadTableData":
        return [{"ip": ip, "dns": name} for name, ip in table]
    if router.drop_writes:
        return ""
    if action == "add":
        table.append((params["hostName"], params["ip"]))
    elif action == "del":
        router.state["dns"] = [row for row in table if row != (params["hostName"], params["ip"])]
    return ""


def _arp(router, action, params):
    if params.get("action") == "get":
        return {"admin": router.state["arp"]}
    if not router.drop_writes:
        router.state["arp"] = params["admin"]
    return ""


def _controls(router, action, params):
    state = router.state["controls"]
    if params.get("action") == "get":
        return dict(state)
    if not router.drop_writes:
        for key in ("sip", "led", "brightness"):
            if key in params:
                state[key] = params[key]
    return ""


def _firewall(router, action, params):
    if not router.drop_writes:
        router.state["params"].update(
            fwLevel=params["fwLevel"], fwStealthMode=str(params["fwStealthMode"]), firewallVal=params["firewallInfo"] + "|"
        )
    return ""


def _advfw_load(router, action, params):
    return {params[0]: [dict(rule) for rule in router.state["chains"].get(params[0], [])]}


def _advfw_apply(router, action, params):
    if not router.drop_writes:
        for chain, rules in params.items():
            router.state["chains"][chain] = [dict(rule) for rule in rules]
    return ""


def _devices(router, action, params):
    if action == "get":
        return {"ipv4": [dict(row) for row in router.state["devices"]], "ipv6": [], "active_count": {"lan": 1}}
    if action == "set" and not router.drop_writes:
        for row in router.state["devices"]:
            if row["macAddress"].lower() == params["mac"].lower():
                row["deviceName"], row["type"] = params["deviceName"], params["type"]
    return ""


def _ping(router, action, params):
    job = router.state["ping"]
    if action == "start_ping":
        if job.get("busy"):
            return "#ERROR_049"
        job.update(polls=0, request=dict(params))
        return ""
    job["polls"] = job.get("polls", 0) + 1
    if "request" not in job:
        return {"status": 0, "result": [], "statistic": {"sent": 0, "receive": 0, "loss": "0%", "min": "--ms", "max": "--ms", "avg": "--ms"}}
    if job["polls"] < 3:
        return {"status": 1, "result": [], "statistic": {}}
    return job["final"]


def _trace(router, action, params):
    job = router.state["trace"]
    if action == "trace":
        job.update(polls=0, request=dict(params))
        return ""
    if action == "cancel":
        job["cancelled"] = True
        return ""
    job["polls"] = job.get("polls", 0) + 1
    if job["polls"] < 3:
        return {"status": 1, "trace": []}
    return job["final"]


def settings_router(**overrides):
    """A fake router with every simple setting in its usual state."""
    router = FakeRouter()
    router.state.update({
        "params": {"enblUpnp": "0", "enblUpnpnat": "0", "ethIpAddress": "192.0.2.1", "ethSubnetMask": "255.255.255.0",
                   "fwLevel": "High", "fwStealthMode": "1", "firewallVal": ""},
        "dmz": None,
        "forwards": [],
        "dns": [],
        "arp": "0",
        "controls": {"sip": 0, "led": 1, "brightness": 100, "brightness_supported": 1},
        "chains": {"dsv4": [], "usv4": [], "dsv6": [], "usv6": []},
        "devices": [{"dhcpPool": "lan", "macAddress": "02:00:00:00:00:aa", "ipAddress": "192.0.2.150",
                     "interfaceType": "Ethernet", "isActive": 1, "deviceName": "printer", "type": "Printer",
                     "fingerPrint": {}}],
        "ping": {"final": {"status": 2, "ip_addr": "192.0.2.9", "packet_size": "32", "source_ip": "", "version": "ipv4",
                           "result": [{"from": "192.0.2.9", "bytes": "40", "time": "1.2ms", "ttl": "64"},
                                      {"from": "192.0.2.9", "bytes": "40", "time": "0.9ms", "ttl": "64"}],
                           "statistic": {"sent": 4, "receive": 4, "loss": "0%", "min": "0.9ms", "max": "1.2ms", "avg": "1.0ms"}}},
        "trace": {"final": {"status": 0, "ip_addr": "192.0.2.9", "mode": "icmp", "reverse_dns": "disabled", "version": "ipv4",
                            "trace": [{"hops": "1  192.0.2.1", "time1": "0.5 ms", "time2": "0.4 ms", "time3": "0.4 ms"},
                                      {"hops": "2  192.0.2.9", "time1": "1.5 ms", "time2": "1.4 ms", "time3": "1.4 ms"}]}},
        "read_endpoints": ("advfw_load.cmd",),
    })
    router.state.update(overrides)
    router.handlers.update({
        "cgi_parameter_value.cmd": _params,
        "advanced_security_upnp.cgi": _upnp,
        "scdmz.cmd": _dmz,
        "portForwardingAssociations.cmd": _forward_list,
        "advancedPortForwarding.cmd": _forward,
        "dns_host_mapping.cmd": _dns,
        "arp_spoof.cmd": _arp,
        "advanced_controls.cmd": _controls,
        "advanced_firewallsettings.cmd": _firewall,
        "advfw_load.cmd": _advfw_load,
        "advfw_apply.cmd": _advfw_apply,
        "device_table.cmd": _devices,
        "ping_test.cmd": _ping,
        "traceroute.cmd": _trace,
    })
    return router


def client_for(router):
    return ExosClient("192.0.2.1", "admin", "pw", request=router)
