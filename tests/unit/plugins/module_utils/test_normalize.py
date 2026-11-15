# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from ansible_collections.workshop144.calix_exos.plugins.module_utils import normalize
from ansible_collections.workshop144.calix_exos.tests.unit import replies


def test_system_maps_named_rows():
    assert normalize.system(replies.SYSTEM) == {
        "model": "GS4227W", "serial": "000000000000", "fsan": "CXNK00000000", "version": "25.4.0",
        "uptime": "3D 0H 59M 58S", "mode": "RG", "role": "Controller", "hostname": "router",
    }


def test_system_missing_rows_are_none():
    assert normalize.system({"system_info": []})["model"] is None
    assert normalize.system(None)["version"] is None


def test_lan_types():
    assert normalize.lan(replies.LAN_PARAMS) == {
        "address": "192.0.2.1", "netmask": "255.255.255.0", "dhcp_enabled": True,
        "pool_start": "192.0.2.100", "pool_end": "192.0.2.249", "lease_seconds": 43200,
    }


def test_lan_dhcp_off_and_bad_lease():
    out = normalize.lan(dict(replies.LAN_PARAMS, enblDhcpSrv="0", dhcpLeasedTime=""))
    assert out["dhcp_enabled"] is False
    assert out["lease_seconds"] is None


def test_reservations_sorted_numerically_and_lower_case():
    assert normalize.reservations(replies.RESERVATIONS) == [
        {"pool": "lan", "mac": "02:00:00:00:00:bb", "ip": "192.0.2.9"},
        {"pool": "lan", "mac": "02:00:00:00:00:cc", "ip": "192.0.2.10"},
        {"pool": "lan", "mac": "02:00:00:00:00:aa", "ip": "192.0.2.150"},
    ]


def test_clients():
    assert normalize.clients(replies.DEVICE_TABLE) == [
        {"mac": "02:00:00:00:00:aa", "ip": "192.0.2.150", "name": "printer", "type": "Printer",
         "interface": "Ethernet", "active": True},
        {"mac": "02:00:00:00:00:dd", "ip": "192.0.2.101", "name": "phone", "type": "Smart Phone",
         "interface": "5GHz", "active": False},
    ]


def test_wifi_joins_status_and_setup():
    out = normalize.wifi(replies.WL_STATUS, replies.SSID_PRIMARY)
    assert out[0] == {"band": "5GHz", "ssid": "example", "enabled": True, "hidden": False,
                      "security": "psk-mixed+aes", "wps": True, "wps_type": "PushButton", "isolation": False}
    assert out[1]["band"] == "2.4GHz" and out[1]["wps"] is False


def test_wifi_includes_ssids_with_no_status_row():
    out = normalize.wifi(replies.WL_STATUS, replies.SSID_PRIMARY)
    assert out[2] == {"band": "6GHz", "ssid": "reserved-6g", "enabled": True, "hidden": False,
                      "security": "wpa3", "wps": None, "wps_type": None, "isolation": False}


def test_wifi_drops_key_material():
    out = normalize.wifi(replies.WL_STATUS, replies.SSID_PRIMARY)
    assert "deadbeef" not in repr(out)
    assert "cafe" not in repr(out)


def test_wifi_empty_replies():
    assert normalize.wifi(None, None) == []


def test_security_types():
    assert normalize.security(replies.SECURITY_PARAMS, None, None) == {
        "upnp": False, "upnp_nat": False, "firewall_level": "High", "stealth_mode": True,
        "dmz_host": None, "port_forwards": [],
    }


def test_security_on_values():
    out = normalize.security(dict(replies.SECURITY_PARAMS, enblUpnp="1", dmzHost="192.0.2.50"), None, [{"a": 1}])
    assert out["upnp"] is True
    assert out["dmz_host"] == "192.0.2.50"
    assert out["port_forwards"] == [{"a": 1}]


def test_wan_is_the_connection_object():
    assert normalize.wan(replies.CONNECTION) == replies.CONNECTION["connection"]
    assert normalize.wan(None) == {}


def test_lan_missing_name_raises():
    import pytest
    from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError
    params = dict(replies.LAN_PARAMS)
    del params["enblDhcpSrv"]
    with pytest.raises(ExosError) as err:
        normalize.lan(params)
    assert "enblDhcpSrv" in str(err.value)
    with pytest.raises(ExosError):
        normalize.lan(None)


def test_security_missing_name_raises():
    import pytest
    from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError
    params = dict(replies.SECURITY_PARAMS)
    del params["enblUpnp"]
    with pytest.raises(ExosError) as err:
        normalize.security(params, None, None)
    assert "enblUpnp" in str(err.value)
    with pytest.raises(ExosError):
        normalize.security({}, None, None)


def test_security_dmz_reply_is_not_ignored():
    out = normalize.security(replies.SECURITY_PARAMS, {"host": "192.0.2.77"}, None)
    assert out["dmz_host"] == {"host": "192.0.2.77"}


def test_reservation_table_must_look_like_one():
    import pytest
    from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError
    for bad in (None, {}, {"foo": 1}, [], {"networks": [], "staticIpLease": "x"}):
        with pytest.raises(ExosError):
            normalize.reservation_table(bad)


def test_reservation_table_without_lease_key_is_empty():
    entries, pools = normalize.reservation_table({"networks": [{"dhcpPool": "lan"}]})
    assert entries == [] and pools == ["lan"]


def test_reservation_table_returns_entries_and_pools():
    entries, pools = normalize.reservation_table(replies.RESERVATIONS)
    assert len(entries) == 3 and pools == ["lan"]
