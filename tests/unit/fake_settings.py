# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Handlers that make FakeRouter behave like the router's settings pages. Values are made up."""

from __future__ import annotations

import hashlib

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
    store["scheduleAccessList"] = "|".join("/".join(row) for row in router.state["schedules"])
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


def _apps(router, action, params):
    return {"scheduleType": router.state["schedule_type"], "apps": [{"name": "CIES", "state": "RUNNING"}]}


def _access(router, action, params):
    table = router.state["schedules"]
    if router.drop_writes:
        return ""
    if params["action"] == "add":
        table.append((params["username"], params["mac"], params.get("days", ""), params.get("start_time", ""), params.get("end_time", "")))
    elif params["action"] == "remove":
        router.state["schedules"] = [row for row in table if row[0] != params["username"]]
    return ""


def _svc_rules(router, action, params):
    return "|".join(
        # a real router writes each entry as PROTO:start:end:1
        "%s,%s,%s" % (name, custom, ";".join(e.upper() + ":1" for e in entries))
        for name, (custom, entries) in router.state["svc_rules"].items()
    )


def _svc_rule(router, action, params):
    rules = router.state["svc_rules"]
    if router.drop_writes:
        return ""
    entry = "%s:%s:%s" % (params.get("protocol"), params.get("portStart"), params.get("portEnd"))
    name = params.get("ruleName")
    if action == "add":
        rules.setdefault(name, ("1", []))[1].append(entry)
    elif action == "remove":
        if name in rules:
            rules[name] = (rules[name][0], [e for e in rules[name][1] if e != entry])
            if not rules[name][1]:
                del rules[name]
    return ""


def _svc_assocs(router, action, params):
    return "|".join("%s,%s" % pair for pair in router.state["svc_assocs"])


def _svc_assoc(router, action, params):
    pair = (params["ipAddress"], params["ruleName"])
    if router.drop_writes:
        return ""
    if action == "add":
        if pair[1] not in router.state["svc_rules"]:
            return "#ERROR_019"
        router.state["svc_assocs"].append(pair)
    elif action == "remove":
        router.state["svc_assocs"] = [p for p in router.state["svc_assocs"] if p != pair]
    return ""


def _ipv6_lan(router, action, params):
    if params["action"] == "load":
        return dict(router.state["ipv6_lan"])
    if not router.drop_writes:
        new = {key: value for key, value in params.items() if key != "action"}
        new.setdefault("advPriDns", "")
        new.setdefault("advSecDns", "")
        router.state["ipv6_lan"] = new
    return ""


def _xor(text_or_hex, ssid, nonce, auth, decrypt=False):
    key = hashlib.sha256(("%s:%s:%s" % (ssid, nonce, auth)).encode()).digest()
    if decrypt:
        data = bytes.fromhex(text_or_hex)
        return "".join(chr(key[i % 32] ^ b) for i, b in enumerate(data))
    return "".join("%02x" % (key[i % 32] ^ ord(c)) for i, c in enumerate(text_or_hex))


READ_NONCE = "ab" * 32


def _wlinfo(router, action, params):
    wifi = router.state["wifi"]
    if action == "get_radio_setup":
        return [dict(radio) for radio in wifi["radios"]]
    if action == "get_status":
        return _wl_status(router)
    if action == "get_pool_status":
        return dict(wifi["pool"])
    if action == "get_ssid_setup" and params.get("wlSsidUsage") == "primary":
        p = wifi["primary"]
        rows = []
        for idx, band in ((1, "5"), (2, "2.4"), (3, "6")):
            ssid = p["ssid"] if band != "6" else "reserved-6g"
            auth = p["auth"] if band != "6" else "wpa3"
            rows.append({"is6Supported": "0", "l2bridge": 0, "wlAPIsolation": 0, "wlAuthMode": auth, "wlBand": band,
                         "wlEnbl": 1, "wlHidden": p["hidden"], "wlRadioEnbl": 1, "wlRadioIdx": idx, "wlSsid": ssid,
                         "wlSsidIdx": 1, "nonce": READ_NONCE,
                         "wlWpaPsk": _xor(p["key"], ssid, READ_NONCE, auth) if auth not in ("disabled", "owe") else ""})
        return rows
    if action == "get_ssid_setup":
        rows = []
        for net in wifi["secondary"]:
            row = dict(net["row"])
            row["nonce"] = READ_NONCE
            row["wlWpaPsk"] = _xor(net["key"], row["wlSsid"], READ_NONCE, row["wlAuthMode"]) if net["key"] else ""
            rows.append(row)
        return rows
    return ""


def _multiplessid(router, action, params):
    wifi = router.state["wifi"]
    if router.drop_writes:
        return ""
    key = ""
    if params.get("wlWpaPsk"):
        key = _xor(params["wlWpaPsk"], params["wlSsid"], params["nonce"], params["wlAuthMode"], decrypt=True)
    if "actiondo" not in params:                      # the primary network
        wifi["primary"] = {"ssid": params["wlSsid"], "auth": params["wlAuthMode"], "hidden": int(params["wlHidden"]), "key": key}
        return ""
    do = str(params["actiondo"])
    if do == "0":
        wifi["secondary"] = [n for n in wifi["secondary"] if n["row"]["wlSsid"] != params["wlSsid"]]
        return ""
    row = {"bandFlag": -1, "is6Supported": "0", "networkType": params["networkType"], "smart_qos": int(params["smart_qos"]),
           "wlAuthMode": params["wlAuthMode"], "wlDisblTime": params.get("wlDisblTime", ""), "wlEnbl": 1,
           "wlEnblTime": params.get("wlEnblTime", ""), "wlEndIp": params.get("wlEndIp", ""), "wlGateway": params.get("wlGateway", ""),
           "wlMask": params.get("wlMask", ""), "wlRadioIdx": 15, "wlSsid": params["wlSsid"], "wlSsidIdx": 3,
           "wlStartIp": params.get("wlStartIp", ""), "wlSubnet": int(params["wlSubnet"])}
    if do == "1":
        if wifi["pool"]["ALL"] < 1:
            return "#ERROR_165"
        wifi["secondary"].append({"row": row, "key": key})
    else:
        for net in wifi["secondary"]:
            if net["row"]["wlSsid"] == params["oldname"]:
                net["row"], net["key"] = row, key
    return ""


def _radiosetup(router, action, params):
    if not router.drop_writes:
        by_band = {r["band"]: r for r in router.state["wifi"]["radios"]}
        for sent in params:
            if sent.get("band") in by_band:
                by_band[sent["band"]].update({k: v for k, v in sent.items() if k != "band"})
    return ""


def _dhcpcfg(router, action, params):
    if router.drop_writes:
        return ""
    store = router.state["params"]
    store.update(dnsHostName=params["dnsHostName"], dnsDomainName=params["dnsDomainName"], enblDhcpSrv=str(params["enblDhcpSrv"]),
                 ethIpAddress=params["dhcpServerIP"], ethSubnetMask=params["dhcpSubnetMask"])
    if str(params["enblDhcpSrv"]) == "1":
        custom = params["dnsType"] == "custom"
        store.update(dhcpEthStart=params["dhcpEthStart"], dhcpEthEnd=params["dhcpEthEnd"], dnsType=params["dnsType"],
                     dhcpLeasedTime=str(params["dhcpLeasedTime"]),
                     dhcpPrimaryDNS=params["dnsPrimary"] if custom else "0.0.0.0",
                     dhcpSecondaryDNS=params["dnsSecondary"] if custom else "0.0.0.0")
    return ""


def _reboot(router, action, params):
    if router.state.get("reboot_ignored"):      # the router answers but does not restart
        return ""
    router.state["rebooted"] = True
    router.state["system"] = {"system_info": [{"param": "Device Uptime", "value": "0D 0H 1M 30S"}]}
    router.logged_in = False
    router.state["down_for"] = router.state.get("boot_polls", 2)
    return ""


def _wl_status(router):
    p = router.state["wifi"]["primary"]
    rows = [{"radioid": i, "ifaceid": 1, "ssid": p["ssid"], "broadcast": 1, "radio": 1, "state": 1, "mode": "11ax",
             "frequency": band, "channelMode": 0, "channel": 1, "secured": 1, "secureType": "psk-mixed+aes",
             "MACAuthFilter": "Disabled", "wps": 1, "wpsType": "PushButton"} for i, band in ((1, "5GHz"), (2, "2.4GHz"))]
    return rows


def _static(key):
    return lambda router, action, params: router.state[key]


def _ddns(router, action, params):
    blank = {"state": "0", "server": "", "user": "", "pwd": "", "hostname": "", "ipsrc": "", "website": ""}
    return {"ipv4": dict(blank, **router.state["ddns"]), "ipv6": dict(blank)}


def settings_router(**overrides):
    """A fake router with every simple setting in its usual state."""
    router = FakeRouter()
    router.state.update({
        "params": {"enblUpnp": "0", "enblUpnpnat": "0", "ethIpAddress": "192.0.2.1", "ethSubnetMask": "255.255.255.0",
                   "dhcpEthStart": "192.0.2.100", "dhcpEthEnd": "192.0.2.249", "dhcpLeasedTime": "43200", "enblDhcpSrv": "1",
                   "enblDhcpReservation": "0", "dnsType": "default", "dnsHostName": "router", "dnsDomainName": "home.example",
                   "dhcpPrimaryDNS": "0.0.0.0", "dhcpSecondaryDNS": "0.0.0.0", "dhcpOptionTftpEn": "0",
                   "dhcpOptionTftpOpt150": "", "dhcpOptionTftpOpt66": "",
                   "fwLevel": "High", "fwStealthMode": "1", "firewallVal": ""},
        "dmz": None,
        "forwards": [],
        "dns": [],
        "arp": "0",
        "controls": {"sip": 0, "led": 1, "brightness": 100, "brightness_supported": 1},
        "chains": {"dsv4": [], "usv4": [], "dsv6": [], "usv6": []},
        "schedule_type": "ewi",
        "ddns": {"state": "1", "server": "dyndns.org", "user": "someone", "pwd": "c0ffee", "nonce": "ab" * 32,
                 "hostname": "home.example.org", "ipsrc": "network"},
        "system": {"system_info": [{"param": "Model Number", "value": "GS4227W"}, {"param": "EXOS Version", "value": "25.4.0"},
                                   {"param": "Device Uptime", "value": "3D 1H 2M 3S"}]},
        "connection": {"connection": {"wan": {"state": 2, "color": "green"}}, "gateway": []},
        "internet": {"status": [{"param": "IPv4 Connection", "value": "Connected", "color": "green"}],
                     "settings": [{"param": "MTU Size", "value": "1500"}],
                     "ipv4_addressing": [{"param": "Device IPv4 Address", "value": "198.51.100.20"},
                                         {"param": "DNS Address #1", "value": "198.51.100.53"}],
                     "ipv6_addressing": [], "_6rd": [], "ds_lite": [], "mapt": []},
        "ports": [{"type": "Ethernet", "rate": "1000M", "port_id": 1, "packetsSent_ipv4": 10, "packetRecv_ipv4": 20,
                   "packetsSent_ipv6": 0, "packetRecv_ipv6": 0},
                  {"type": "Ethernet", "rate": "Disconnected", "port_id": 2, "packetsSent_ipv4": 0, "packetRecv_ipv4": 0,
                   "packetsSent_ipv6": 0, "packetRecv_ipv6": 0}],
        "wifi": {
            "radios": [
                {"160_80+80": "0", "802.11ax": "1", "band": "5G", "dfs": "1", "enable": "1", "is6Supported": "0", "mimo": "0",
                 "psc_only": "0", "support_160": "0", "support_dfs": "1", "support_mimo": "1"},
                {"802.11ax": "1", "band": "2.4G", "dfs": "0", "enable": "1", "is6Supported": "0", "mimo": "0", "psc_only": "0",
                 "support_dfs": "0", "support_mimo": "1"},
                {"160_80+80": "1", "802.11ax": "1", "afc_enable": 0, "band": "6G", "dfs": "0", "enable": "1",
                 "is6Supported": "0", "isAfcSupported": 0, "mimo": "0", "psc_only": "1", "support_dfs": "0", "support_mimo": "1"},
            ],
            "pool": {"2G": 3, "2GIP": 23, "5G": 3, "5GIP": 13, "6G": 0, "6GIP": 33, "ALL": 3, "ALLIP": 13,
                     "is6Supported": "0", "smartqos": 0, "wfh_enable": 0},
            "primary": {"ssid": "example", "auth": "psk+psk2", "hidden": 0, "key": "correct horse battery"},
            "secondary": [],
        },
        "schedules": [],
        "svc_rules": {},
        "svc_assocs": [],
        "ipv6_lan": {"ra": "server", "dhcpv6": "server", "dhcpv6Mode": "both", "dns6Type": "default",
                     "advPriDns": "", "advSecDns": "", "somethingElse": "kept"},
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
        "read_endpoints": ("advfw_load.cmd", "apps_status.cmd", "status_lanstatus_ipv6.cmd"),
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
        "apps_status.cmd": _apps,
        "detail_access.cmd": _access,
        "serviceBlockingRules.cmd": _svc_rules,
        "serviceBlockingRule.cmd": _svc_rule,
        "serviceBlockingAssociations.cmd": _svc_assocs,
        "serviceBlockingAssociation.cmd": _svc_assoc,
        "lan_setting_ipv6.cmd": _ipv6_lan,
        "wlinfo.cmd": _wlinfo,
        "wireless_multiplessid.wl": _multiplessid,
        "wireless_radiosetup.wl": _radiosetup,
        "dhcpcfg.cmd": _dhcpcfg,
        "rebootinfo.cgi": _reboot,
        "get_nonce.cmd": lambda router, action, params: "cd" * 32,
        "status_system.cmd": _static("system"),
        "status_connection.cmd": _static("connection"),
        "internet_status.cmd": _static("internet"),
        "status_lanstatus_ipv6.cmd": _static("ports"),
        "ddnsmngr.cmd": _ddns,
        "traceroute.cmd": _trace,
    })
    return router


def client_for(router):
    return ExosClient("192.0.2.1", "admin", "pw", request=router)
