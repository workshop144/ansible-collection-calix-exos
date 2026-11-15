# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Reading and writing the router's Wi-Fi settings.

Wi-Fi keys travel encrypted in both directions (see ``encrypt_secret``). Nothing here returns a
key to a module's result; modules compare keys and say only whether one changed.
"""

from __future__ import annotations

import re

from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, flag
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError, decrypt_secret, encrypt_secret

# what a playbook says -> what the router calls it
SECURITY = {
    "wpa2-wpa3": "wpa3-mixed",
    "wpa3": "wpa3",
    "wpa-wpa2": "psk+psk2",
    "wpa2": "psk2",
    "enhanced-open": "owe",
    "none": "disabled",
}
SECURITY_NAMES = {wire: name for name, wire in SECURITY.items()}
KEYLESS = ("owe", "disabled")
SETTLE_TRIES = 15      # the radios restart after a change; the new state can take a while to show
SETTLE_DELAY = 3


def check_ssid(value):
    name = str(value)
    if not 1 <= len(name) <= 32 or not re.fullmatch(r"[\x00-\xff]+", name):
        raise ExosModuleError("a network name is 1 to 32 characters")
    return name


def check_key(value):
    key = str(value)
    if not re.fullmatch(r"(?=.*\S)[\x20-\x7e]{8,63}", key):
        raise ExosModuleError("a Wi-Fi key is 8 to 63 printable ASCII characters")
    return key


def security_name(wire):
    return SECURITY_NAMES.get(wire, wire)


def stored_key(row):
    """The key the router holds for a network row, decrypted, or "" when it has none."""
    cipher, nonce = row.get("wlWpaPsk"), row.get("nonce")
    if not cipher or not nonce or row.get("wlAuthMode") in KEYLESS:
        return ""
    try:
        return decrypt_secret(cipher, row.get("wlSsid"), nonce, row.get("wlAuthMode"))
    except ValueError:
        return ""


def encrypted(client, ssid, wire_security, key):
    """``(cipher, nonce)`` for a key, or ``("", None)`` for a network without one."""
    if wire_security in KEYLESS or not key:
        return "", None
    nonce = client.nonce()
    try:
        return encrypt_secret(key, ssid, nonce, wire_security), nonce
    except ValueError as err:
        raise ExosModuleError(str(err)) from None


def _rows(client, usage):
    reply = client.call("wlinfo.cmd", action="get_ssid_setup", wlSsidUsage=usage)
    if reply is None:
        return []
    if not isinstance(reply, list):
        raise ExosError("the router did not return its %s Wi-Fi networks" % usage, endpoint="wlinfo.cmd", action="get_ssid_setup")
    return [row for row in reply if isinstance(row, dict)]


def primary_row(client):
    """The row the admin page edits for the primary network: the 2.4 GHz one."""
    rows = _rows(client, "primary")
    row = next((r for r in rows if str(r.get("wlBand")) == "2.4"), rows[0] if rows else None)
    if row is None or "wlSsid" not in row or "wlAuthMode" not in row:
        raise ExosError("the router did not return its primary Wi-Fi network", endpoint="wlinfo.cmd", action="get_ssid_setup")
    return row


def public_primary(row):
    return {"ssid": row["wlSsid"], "security": security_name(row["wlAuthMode"]), "hidden": flag(row.get("wlHidden", 0))}


def secondary_rows(client):
    return _rows(client, "guest")


KINDS = {"guest": "guest", "work_from_home": "wfh", "custom": "custom"}
BANDS = {"2.4": "24", "5": "5", "6": "6", "all": "unified"}
POOL_KEYS = {"24": "2G", "5": "5G", "6": "6G", "unified": "ALL"}


def split_type(network_type):
    """``(kind, band)`` in playbook terms from the router's networkType."""
    text = str(network_type)
    kinds = {wire: name for name, wire in KINDS.items()}
    bands = {wire: name for name, wire in BANDS.items()}
    if text.startswith("custom_"):
        return "custom", bands.get(text.split("_", 1)[1], "all")
    return kinds.get(text, text), "all"


def public_secondary(row):
    kind, band = split_type(row.get("networkType"))
    return {"ssid": row["wlSsid"], "kind": kind, "band": band, "security": security_name(row.get("wlAuthMode")),
            "isolation": flag(row.get("wlSubnet", 0))}


def pool_status(client):
    reply = client.call("wlinfo.cmd", action="get_pool_status", wlSsidUsage="guest")
    if not isinstance(reply, dict) or "ALL" not in reply:
        raise ExosError("the router did not say how many more Wi-Fi networks it can hold", endpoint="wlinfo.cmd", action="get_pool_status")
    return reply


# ---- radios

RADIO_BANDS = {"2.4": "2.4G", "5": "5G", "6": "6G"}
RADIO_OPTIONS = {   # option -> the router's key
    "enabled": "enable",
    "dfs": "dfs",
    "mu_mimo": "mimo",
    "psc_only": "psc_only",
    "wifi6": "802.11ax",
    "wifi7": "802.11be",
    "wide_channels": "160_80+80",
}
ALWAYS_SENT = ("enable", "dfs", "mimo", "psc_only")
OPTIONAL_SENT = ("802.11ax", "802.11be", "160_80+80", "320")


def radios(client):
    reply = client.call("wlinfo.cmd", action="get_radio_setup")
    if not isinstance(reply, list) or not all(isinstance(r, dict) and "enable" in r for r in reply):
        raise ExosError("the router did not return its radios", endpoint="wlinfo.cmd", action="get_radio_setup")
    return reply


def radio_band(raw):
    band = str(raw.get("band", ""))
    return band if band in ("5G", "6G") else "2.4G"


def public_radio(raw):
    out = {"band": {wire: name for name, wire in RADIO_BANDS.items()}[radio_band(raw)]}
    for option, key in RADIO_OPTIONS.items():
        if key in raw:
            out[option] = flag(raw[key])
    return out


def radio_payload(raw_radios):
    """The whole array the admin page posts: 2.4, 5, 6 GHz, flags as "1"/"0"."""
    by_band = {radio_band(raw): raw for raw in raw_radios}
    payload = []
    for band in ("2.4G", "5G", "6G"):
        raw = by_band.get(band)
        if raw is None:
            payload.append({key: "0" for key in ALWAYS_SENT})   # what the page sends for a radio the router lacks
            continue
        entry = {"enable": "1" if flag(raw["enable"]) else "0", "band": raw.get("band")}
        for key in ALWAYS_SENT[1:]:
            entry[key] = "1" if flag(raw.get(key, 0)) else "0"
        for key in OPTIONAL_SENT:
            if key in raw:
                entry[key] = "1" if flag(raw[key]) else "0"
        if flag(raw.get("isAfcSupported", 0)):
            entry["afc_enable"] = "1" if flag(raw.get("afc_enable", 0)) else "0"
        payload.append(entry)
    return payload
