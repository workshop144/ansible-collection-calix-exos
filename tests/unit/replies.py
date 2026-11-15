# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Example router replies. Shapes are as observed on EXOS 25.4.0; every value is made up."""

from __future__ import annotations

import json

SYSTEM = {
    "system_info": [
        {"param": "Current Local Time", "value": "Sun Jan  4 12:00:00 2026"},
        {"param": "Model Number", "value": "GS4227W"},
        {"param": "FSAN", "value": "CXNK00000000"},
        {"param": "Serial Number", "value": "000000000000"},
        {"param": "Host Name", "value": "router"},
        {"param": "Device Uptime", "value": "3D 0H 59M 58S"},
        {"param": "EXOS Version", "value": "25.4.0"},
        {"param": "Operational Mode", "value": "RG"},
        {"param": "Operational Role", "value": "Controller"},
    ],
    "cpu_info": [],
    "mem_info": {},
    "space_info": {},
}

LAN_PARAMS = {
    "ethIpAddress": "192.0.2.1",
    "ethSubnetMask": "255.255.255.0",
    "enblDhcpSrv": "1",
    "dhcpEthStart": "192.0.2.100",
    "dhcpEthEnd": "192.0.2.249",
    "dhcpLeasedTime": "43200",
}

RESERVATIONS = {
    "networks": [{"network": "Primary", "dhcpPool": "lan", "dhcpEnbled": "1",
                  "dhcpStart": "192.0.2.100", "dhcpEnd": "192.0.2.249"}],
    "staticIpLease": [
        {"dhcpPool": "lan", "ip": "192.0.2.150", "mac": "02:00:00:00:00:AA"},
        {"dhcpPool": "lan", "ip": "192.0.2.9", "mac": "02:00:00:00:00:bb"},
        {"dhcpPool": "lan", "ip": "192.0.2.10", "mac": "02:00:00:00:00:cc"},
    ],
}

DEVICE_TABLE = {
    "ipv4": [
        {"dhcpPool": "lan", "macAddress": "02:00:00:00:00:AA", "ipAddress": "192.0.2.150",
         "interfaceType": "Ethernet", "isActive": 1, "deviceName": "printer", "type": "Printer",
         "fingerPrint": {}},
        {"dhcpPool": "lan", "macAddress": "02:00:00:00:00:dd", "ipAddress": "192.0.2.101",
         "interfaceType": "5GHz", "isActive": 0, "deviceName": "phone", "type": "Smart Phone",
         "fingerPrint": {}},
    ],
    "active_count": {"lan": 1},
    "ipv6": [],
}

WL_STATUS = [
    {"radioid": 1, "ifaceid": 1, "ssid": "example", "broadcast": 1, "radio": 1, "state": 1,
     "mode": "11ax", "frequency": "5GHz", "channelMode": 0, "channel": 149, "secured": 1,
     "secureType": "psk-mixed+aes", "MACAuthFilter": "Disabled", "wps": 1, "wpsType": "PushButton",
     "wirelessPacketsSent": 1, "wirelessPacketsReceived": 1},
    {"radioid": 2, "ifaceid": 1, "ssid": "example", "broadcast": 1, "radio": 1, "state": 1,
     "mode": "11ax", "frequency": "2.4GHz", "channelMode": 0, "channel": 6, "secured": 1,
     "secureType": "psk-mixed+aes", "MACAuthFilter": "Disabled", "wps": 0, "wpsType": "PushButton",
     "wirelessPacketsSent": 1, "wirelessPacketsReceived": 1},
]

SSID_ROW = {"is6Supported": "0", "wlRadioIdx": 1, "wlBand": "5", "wlRadioEnbl": 1, "wlSsidIdx": 1,
            "wlSsid": "example", "wlHidden": 0, "wlEnbl": 1, "wlAPIsolation": 0, "l2bridge": 0,
            "wlAuthMode": "psk+psk2", "nonce": "cafe" * 16, "wlWpaPsk": "deadbeef" * 4}

SSID_PRIMARY = [
    SSID_ROW,
    dict(SSID_ROW, wlRadioIdx=2, wlBand="2.4"),
    dict(SSID_ROW, wlRadioIdx=3, wlBand="6", wlSsid="reserved-6g", wlAuthMode="wpa3"),
]

SECURITY_PARAMS = {"enblUpnp": "0", "enblUpnpnat": "0", "fwLevel": "High", "fwStealthMode": "1", "dmzHost": ""}

CONNECTION = {"connection": {"wan": {"state": 2, "color": "green"}, "ipv4": {"state": 2, "color": "green"},
                             "ipv6": {"state": 2, "color": "green"}}, "gateway": []}


def canned():
    """Replies for FakeRouter covering every read the info module makes."""
    return {
        ("status_system.cmd", "get"): json.dumps(SYSTEM),
        ("cgi_parameter_value.cmd", "get"): json.dumps(dict(LAN_PARAMS, **SECURITY_PARAMS)),
        ("device_table.cmd", "get"): json.dumps(DEVICE_TABLE),
        ("wlinfo.cmd", "get_status"): json.dumps(WL_STATUS),
        ("wlinfo.cmd", "get_ssid_setup"): json.dumps(SSID_PRIMARY),
        ("scdmz.cmd", "get"): "",
        ("portForwardingAssociations.cmd", "readall"): "",
        ("status_connection.cmd", "getStatus"): json.dumps(CONNECTION),
    }
