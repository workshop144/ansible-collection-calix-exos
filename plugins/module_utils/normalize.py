# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Turn the router's raw replies into plain, typed data. No network access here."""

from __future__ import annotations

from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError, normalize_mac

SUBSETS = ("system", "lan", "dhcp_reservations", "clients", "wifi", "security", "wan")

LAN_PARAMS = ("ethIpAddress", "ethSubnetMask", "enblDhcpSrv", "dhcpEthStart", "dhcpEthEnd", "dhcpLeasedTime")
SECURITY_PARAMS = ("enblUpnp", "enblUpnpnat", "fwLevel", "fwStealthMode")
# Read with ejGetOtherVal: the router does not return these for ejGetVal.
SECURITY_OTHER_PARAMS = ("dmzHost",)

SYSTEM_ROWS = {
    "Model Number": "model",
    "Serial Number": "serial",
    "FSAN": "fsan",
    "EXOS Version": "version",
    "Device Uptime": "uptime",
    "Operational Mode": "mode",
    "Operational Role": "role",
    "Host Name": "hostname",
}


def _flag(value):
    return str(value).strip().lower() in ("1", "true", "on", "yes", "enabled")


def _int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _mac(value):
    try:
        return normalize_mac(value)
    except ValueError:
        return value


def _ip_key(address):
    try:
        return (0, tuple(int(part) for part in str(address).split(".")))
    except ValueError:
        return (1, str(address))


def _require(params, names):
    """Fail rather than read a missing setting as off: the router answers an unknown name with {}."""
    params = params if isinstance(params, dict) else {}
    missing = [name for name in names if name not in params]
    if missing:
        raise ExosError(
            "the router did not return %s; this firmware may name these settings differently"
            % ", ".join(missing),
            endpoint="cgi_parameter_value.cmd", action="get",
        )
    return params


def _rows(raw, key=None):
    if key is not None:
        raw = raw.get(key) if isinstance(raw, dict) else None
    return [row for row in raw if isinstance(row, dict)] if isinstance(raw, list) else []


def system(raw):
    out = dict.fromkeys(SYSTEM_ROWS.values())
    for row in _rows(raw, "system_info"):
        name = SYSTEM_ROWS.get(row.get("param"))
        if name:
            out[name] = row.get("value")
    return out


def lan(params):
    params = _require(params, LAN_PARAMS)
    return {
        "address": params.get("ethIpAddress"),
        "netmask": params.get("ethSubnetMask"),
        "dhcp_enabled": _flag(params.get("enblDhcpSrv")),
        "pool_start": params.get("dhcpEthStart"),
        "pool_end": params.get("dhcpEthEnd"),
        "lease_seconds": _int(params.get("dhcpLeasedTime")),
    }


def reservation_table(raw):
    """Return ``(reservations, pool names)``. Fails on anything that is not a reservation table,

    so that an empty or broken reply is never mistaken for an empty table.
    """
    networks = raw.get("networks") if isinstance(raw, dict) else None
    leases = raw.get("staticIpLease", []) if isinstance(raw, dict) else None
    if not isinstance(networks, list) or not networks or not isinstance(leases, list):
        raise ExosError(
            "the router did not return a DHCP reservation table",
            endpoint="dhcp_reservation.cmd", action="init",
        )
    entries = [
        {"pool": row.get("dhcpPool"), "mac": _mac(row.get("mac")), "ip": row.get("ip")}
        for row in _rows(leases)
    ]
    pools = [row.get("dhcpPool") for row in _rows(networks)]
    return sorted(entries, key=lambda entry: _ip_key(entry["ip"])), pools


def reservations(raw):
    return reservation_table(raw)[0]


def clients(raw):
    return [
        {
            "mac": _mac(row.get("macAddress")),
            "ip": row.get("ipAddress"),
            "name": row.get("deviceName"),
            "type": row.get("type"),
            "interface": row.get("interfaceType"),
            "active": _flag(row.get("isActive")),
        }
        for row in _rows(raw, "ipv4")
    ]


def _band(value):
    text = str(value).strip()
    return text if text.lower().endswith("ghz") else text + "GHz"


def wifi(status, ssids):
    """One entry per SSID per band. Key material in the setup rows is never copied."""
    setup = {}
    for row in _rows(ssids):
        setup.setdefault((_band(row.get("wlBand")), row.get("wlSsid")), row)
    out = []
    for row in _rows(status):
        key = (_band(row.get("frequency")), row.get("ssid"))
        match = setup.pop(key, None)
        out.append({
            "band": key[0],
            "ssid": key[1],
            "enabled": _flag(row.get("state")),
            "hidden": _flag(match.get("wlHidden")) if match else not _flag(row.get("broadcast")),
            "security": row.get("secureType"),
            "wps": _flag(row.get("wps")),
            "wps_type": row.get("wpsType"),
            "isolation": _flag(match.get("wlAPIsolation")) if match else None,
        })
    for (band, ssid), row in setup.items():
        out.append({
            "band": band,
            "ssid": ssid,
            "enabled": _flag(row.get("wlEnbl")),
            "hidden": _flag(row.get("wlHidden")),
            "security": row.get("wlAuthMode"),
            "wps": None,
            "wps_type": None,
            "isolation": _flag(row.get("wlAPIsolation")),
        })
    return out


def _dmz_host(value):
    """The router reports the DMZ setting as ``<on>|<host>``; ``0|`` means none is set."""
    text = str(value or "").strip()
    if "|" not in text:
        return text or None
    enabled, host = text.split("|", 1)
    if not _flag(enabled):
        return None
    return host.strip() or text


def security(params, dmz, forwards):
    params = _require(params, SECURITY_PARAMS + SECURITY_OTHER_PARAMS)
    if isinstance(forwards, dict):
        forwards = [forwards]
    return {
        "upnp": _flag(params.get("enblUpnp")),
        "upnp_nat": _flag(params.get("enblUpnpnat")),
        "firewall_level": params.get("fwLevel"),
        "stealth_mode": _flag(params.get("fwStealthMode")),
        # scdmz.cmd is empty when no DMZ host is set; anything it does return is passed through.
        "dmz_host": _dmz_host(params.get("dmzHost")) or dmz or None,
        "port_forwards": forwards if isinstance(forwards, list) else [],
    }


def wan(raw):
    connection = raw.get("connection") if isinstance(raw, dict) else None
    return connection if isinstance(connection, dict) else {}
