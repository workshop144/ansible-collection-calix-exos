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


def settings_router(**overrides):
    """A fake router with every simple setting in its usual state."""
    router = FakeRouter()
    router.state.update({
        "params": {"enblUpnp": "0", "enblUpnpnat": "0", "ethIpAddress": "192.0.2.1", "ethSubnetMask": "255.255.255.0"},
        "dmz": None,
        "forwards": [],
        "dns": [],
        "arp": "0",
        "controls": {"sip": 0, "led": 1, "brightness": 100, "brightness_supported": 1},
        "read_endpoints": (),
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
    })
    return router


def client_for(router):
    return ExosClient("192.0.2.1", "admin", "pw", request=router)
