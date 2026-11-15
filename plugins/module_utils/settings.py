# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Reading (and the raw writes for) the router's simpler settings.

Each ``read_*`` returns plain typed data and fails, rather than guessing, when the router's reply
does not carry what was asked for. The ``info`` module and the settings modules share them.
"""

from __future__ import annotations

import ipaddress

from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, flag
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError

PARAMS = "cgi_parameter_value.cmd"


def params(client, names=(), other=()):
    """Read named settings. ``other`` are the names the router only returns for ejGetOtherVal."""
    fields = {"action": "get"}
    if names:
        fields["ejGetVal"] = ",".join(names)
    if other:
        fields["ejGetOtherVal"] = ",".join(other)
    reply = client.call(PARAMS, **fields)
    reply = reply if isinstance(reply, dict) else {}
    missing = [name for name in tuple(names) + tuple(other) if name not in reply]
    if missing:
        raise ExosError(
            "the router did not return %s; this firmware may name these settings differently" % ", ".join(missing),
            endpoint=PARAMS, action="get",
        )
    return reply


def ipv4(value, what="address"):
    """A canonical IPv4 address, or a module error naming what was wrong."""
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError:
        raise ExosModuleError("not an IPv4 %s: %r" % (what, value)) from None


def port(value, what="port"):
    try:
        number = int(str(value).strip())
    except ValueError:
        number = 0
    if not 1 <= number <= 65535:
        raise ExosModuleError("%s must be between 1 and 65535, not %r" % (what, value))
    return number


# ---- UPnP

def read_upnp(client):
    reply = params(client, names=("enblUpnp", "enblUpnpnat"))
    return {"enabled": flag(reply["enblUpnp"]), "nat_t": flag(reply["enblUpnpnat"])}


def write_upnp(client, enabled, nat_t):
    client.call_text("advanced_security_upnp.cgi", enblUpnp=int(enabled), enblUpnpnat=int(nat_t))


# ---- DMZ

def parse_dmz(value):
    """``<on>|<host>``; ``0|`` means none is set."""
    text = str(value or "").strip()
    if "|" not in text:
        return text or None
    enabled, host = text.split("|", 1)
    if not flag(enabled):
        return None
    return host.strip() or text


def read_dmz(client):
    return parse_dmz(params(client, other=("dmzHost",))["dmzHost"])


# ---- port forwarding

PROTOCOLS = {"tcp": "TCP", "udp": "UDP", "both": "TCP/UDP"}


def _protocol(value):
    text = str(value).strip().upper()
    return {"TCP": "tcp", "UDP": "udp"}.get(text, "both")


def read_port_forwards(client):
    """Port forwarding rules. ``remote`` is the internet side, ``local`` the device on the LAN."""
    text = client.call_text("portForwardingAssociations.cmd", action="readall").strip()
    rules = []
    for record in [r for r in text.split("|") if r.strip()]:
        fields = [f.strip() for f in record.split(",")]
        if len(fields) != 7:
            raise ExosError(
                "unexpected port forwarding record from the router: %r" % record[:80],
                endpoint="portForwardingAssociations.cmd", action="readall",
            )
        remote = fields[4]
        rules.append({
            "protocol": _protocol(fields[0]),
            "local_ip": fields[1],
            "local_port": int(fields[2]),
            "local_port_end": int(fields[3]),
            "remote_ip": None if remote in ("", "0.0.0.0") else remote,
            "remote_port": int(fields[5]),
            "remote_port_end": int(fields[6]),
            "_remote_raw": remote,
        })
    return rules


def port_forward_fields(rule, remote_raw=None):
    """The form fields the router takes to add or remove one rule."""
    remote = remote_raw if remote_raw is not None else (rule["remote_ip"] or "")
    return {
        "protocol": PROTOCOLS[rule["protocol"]],
        "localIpAddress": rule["local_ip"],
        "localPortStart": rule["local_port"],
        "localPortEnd": rule["local_port_end"],
        "remoteIpAddress": remote,
        "remotePortStart": rule["remote_port"],
        "remotePortEnd": rule["remote_port_end"],
    }


def public_rule(rule):
    return {key: value for key, value in rule.items() if not key.startswith("_")}


# ---- DNS host mappings

def read_dns_mappings(client):
    reply = client.call("dns_host_mapping.cmd", action="loadTableData")
    if reply is None:
        return []
    if not isinstance(reply, list):
        raise ExosError(
            "the router did not return a DNS host mapping table",
            endpoint="dns_host_mapping.cmd", action="loadTableData",
        )
    return sorted(
        ({"hostname": str(row.get("dns", "")), "ip": str(row.get("ip", ""))} for row in reply if isinstance(row, dict)),
        key=lambda entry: entry["hostname"].lower(),
    )


# ---- ARP spoofing protection

def read_arp_spoofing(client):
    reply = client.call_json("arp_spoof.cmd", {"action": "get"})
    if not isinstance(reply, dict) or "admin" not in reply:
        raise ExosError("the router did not return its ARP spoofing setting", endpoint="arp_spoof.cmd", action="get")
    return flag(reply["admin"])


# ---- controls (LED, SIP ALG)

def read_controls(client):
    reply = client.call_json("advanced_controls.cmd", {"action": "get", "type": "all"})
    reply = reply if isinstance(reply, dict) else {}
    missing = [name for name in ("sip", "led") if name not in reply]
    if missing:
        raise ExosError(
            "the router did not return %s" % ", ".join(missing), endpoint="advanced_controls.cmd", action="get"
        )
    dimmable = flag(reply.get("brightness_supported", 0))
    brightness = reply.get("brightness")
    return {
        "led": flag(reply["led"]),
        "brightness": int(brightness) if dimmable and brightness is not None else None,
        "sip_alg": flag(reply["sip"]),
    }


# ---- firewall level

FIREWALL_LEVELS = {"Basic": "off", "Low": "low", "Medium": "medium", "High": "high"}


def read_firewall(client):
    reply = params(client, names=("fwLevel", "fwStealthMode"))
    level = FIREWALL_LEVELS.get(str(reply["fwLevel"]))
    if level is None:
        raise ExosError("the router reports a firewall level this collection does not know: %r" % (reply["fwLevel"],),
                        endpoint=PARAMS, action="get")
    return {"level": level, "stealth_mode": flag(reply["fwStealthMode"])}


# ---- custom firewall rules (the Advanced Firewall page)

CHAINS = {"ipv4_in": "dsv4", "ipv4_out": "usv4", "ipv6_in": "dsv6", "ipv6_out": "usv6"}
RULE_PROTOCOLS = {"tcp": "tcp", "udp": "udp", "both": "tcpudp"}


def read_chain(client, chain):
    """The raw rule list of one chain, in match order."""
    wire = CHAINS[chain]
    reply = client.call_json("advfw_load.cmd", [wire])
    rules = reply.get(wire) if isinstance(reply, dict) else None
    if not isinstance(rules, list):
        raise ExosError("the router did not return the %s firewall chain" % chain, endpoint="advfw_load.cmd")
    return [dict(rule) for rule in rules if isinstance(rule, dict)]


def public_firewall_rule(chain, raw):
    protocols = {wire: name for name, wire in RULE_PROTOCOLS.items()}
    return {
        "chain": chain,
        "name": raw.get("name"),
        "source": raw.get("srcip") or None,
        "destination": raw.get("dstip") or None,
        "protocol": protocols.get(str(raw.get("proto", "")).lower(), raw.get("proto")),
        "source_port": raw.get("sport") or None,
        "destination_port": raw.get("dport") or None,
        "action": str(raw.get("action", "")).lower(),
    }


# ---- known devices

def read_devices(client):
    reply = client.call("device_table.cmd", action="get")
    rows = reply.get("ipv4") if isinstance(reply, dict) else reply
    if not isinstance(rows, list):
        raise ExosError("the router did not return its device table", endpoint="device_table.cmd", action="get")
    return [row for row in rows if isinstance(row, dict)]


# ---- parental controls

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def require_local_parental_controls(client):
    """The router refuses these pages when the provider's app manages parental controls."""
    reply = client.call("apps_status.cmd")
    kind = reply.get("scheduleType") if isinstance(reply, dict) else None
    if kind != "ewi":
        raise ExosModuleError(
            "parental controls on this router are managed by the provider's app (schedule type %r), "
            "so the router's own page, and this module, cannot change them" % (kind,)
        )


def read_access_schedules(client):
    """Times at which a device is cut off from the internet. No days means always."""
    text = str(params(client, other=("scheduleAccessList",))["scheduleAccessList"] or "")
    out = []
    for record in [r for r in text.split("|") if r.strip()]:
        fields = record.split("/")
        if len(fields) != 5:
            raise ExosError("unexpected access schedule record from the router: %r" % record[:80], endpoint=PARAMS, action="get")
        days = sorted({d.strip().lower()[:3] for d in fields[2].split(",") if d.strip()}, key=DAYS.index)
        out.append({"_id": fields[0], "mac": fields[1].lower(), "days": days,
                    "start": fields[3] or None, "end": fields[4] or None})
    return out


def _service_protocol(value):
    text = str(value).strip().lower().replace("/", "")
    return {"tcp": "tcp", "udp": "udp", "tcpudp": "both"}.get(text, text)


def read_service_rules(client):
    """Named sets of ports that can be blocked per device. ``custom`` is false for built-in sets."""
    text = client.call_text("serviceBlockingRules.cmd", action="readall").strip()
    rules = {}
    for record in [r for r in text.split("|") if r.strip()]:
        fields = record.split(",", 2)
        if len(fields) != 3:
            raise ExosError("unexpected service rule record from the router: %r" % record[:80],
                            endpoint="serviceBlockingRules.cmd", action="readall")
        ports = []
        for entry in [e for e in fields[2].split(";") if e.strip()]:
            parts = entry.split(":")
            if len(parts) != 3:
                raise ExosError("unexpected service rule entry from the router: %r" % entry[:80],
                                endpoint="serviceBlockingRules.cmd", action="readall")
            ports.append({"protocol": _service_protocol(parts[0]), "port": int(parts[1]), "port_end": int(parts[2])})
        rules[fields[0]] = {"name": fields[0], "custom": flag(fields[1]), "ports": ports}
    return rules


def read_service_blocks(client):
    text = client.call_text("serviceBlockingAssociations.cmd", action="readall").strip()
    out = []
    for record in [r for r in text.split("|") if r.strip()]:
        fields = record.split(",", 1)
        if len(fields) != 2:
            raise ExosError("unexpected service blocking record from the router: %r" % record[:80],
                            endpoint="serviceBlockingAssociations.cmd", action="readall")
        out.append({"ip": fields[0], "rule": fields[1]})
    return out


# ---- IPv6 on the LAN

def read_ipv6_lan_raw(client):
    reply = client.call_json("lan_setting_ipv6.cmd", {"action": "load"})
    reply = reply if isinstance(reply, dict) else {}
    missing = [name for name in ("ra", "dhcpv6", "dhcpv6Mode", "dns6Type") if name not in reply]
    if missing:
        raise ExosError("the router did not return %s" % ", ".join(missing), endpoint="lan_setting_ipv6.cmd", action="load")
    return reply


def public_ipv6_lan(raw):
    custom = raw.get("dns6Type") == "custom"
    return {
        "router_advertisement": raw["ra"] == "server",
        "dhcpv6": raw["dhcpv6"] == "server",
        "dhcpv6_mode": raw["dhcpv6Mode"],
        "dns_servers": [value for value in (raw.get("advPriDns"), raw.get("advSecDns")) if value] if custom else [],
    }
