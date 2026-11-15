# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import pytest

from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosClient, ExosError
from ansible_collections.workshop144.calix_exos.plugins.module_utils.normalize import SUBSETS
from ansible_collections.workshop144.calix_exos.plugins.modules import info
from ansible_collections.workshop144.calix_exos.tests.unit import replies
from ansible_collections.workshop144.calix_exos.tests.unit.fakes import FakeRouter


FIRST = ("system", "lan", "dhcp_reservations", "clients", "wifi", "security", "wan")


def make(router):
    return ExosClient("192.0.2.1", "admin", "pw", request=router)


def test_subset_only_calls_its_endpoints():
    router = FakeRouter(replies=replies.canned())
    result = info.run({"gather_subset": ["system"]}, make(router))
    assert list(result["exos"]) == ["system"]
    assert "status_system.cmd" in router.endpoints()
    assert "wlinfo.cmd" not in router.endpoints()
    assert "device_table.cmd" not in router.endpoints()


def test_first_release_subsets_from_canned_replies():
    router = FakeRouter(replies=replies.canned(), leases=replies.RESERVATIONS["staticIpLease"])
    result = info.run({"gather_subset": list(FIRST)}, make(router))
    assert set(result["exos"]) == set(FIRST)
    assert result["exos"]["system"]["model"] == "GS4227W"
    assert result["exos"]["security"]["upnp"] is False
    assert len(result["exos"]["dhcp_reservations"]) == 3


def test_never_changed():
    router = FakeRouter(replies=replies.canned())
    assert info.run({"gather_subset": list(FIRST)}, make(router))["changed"] is False


def test_no_secret_in_result():
    router = FakeRouter(replies=replies.canned())
    result = info.run({"gather_subset": list(FIRST)}, make(router))
    assert "deadbeef" not in repr(result)
    assert "pw" not in repr(result["exos"]["wifi"])


def test_guest_ssids_are_read_too():
    router = FakeRouter(replies=replies.canned())
    info.run({"gather_subset": ["wifi"]}, make(router))
    usages = [c[1].get("wlSsidUsage") for c in router.calls if c[1].get("action") == "get_ssid_setup"]
    assert usages == ["primary", "guest"]


def test_logs_out_on_error():
    router = FakeRouter(replies=replies.canned())
    router.fail_next("status_system.cmd", "get", "#ERROR_019")
    with pytest.raises(ExosError):
        info.run({"gather_subset": list(FIRST)}, make(router))
    assert router.endpoints()[-1] == "logout.cgi"


def test_unknown_parameter_reply_fails_instead_of_reading_as_off():
    canned = replies.canned()
    canned[("cgi_parameter_value.cmd", "get")] = "{ }"
    router = FakeRouter(replies=canned)
    with pytest.raises(ExosError):
        info.run({"gather_subset": ["security"]}, make(router))


def test_empty_reservation_reply_fails():
    router = FakeRouter(replies=replies.canned())
    router.fail_next("dhcp_reservation.cmd", "init", "")
    with pytest.raises(ExosError):
        info.run({"gather_subset": ["dhcp_reservations"]}, make(router))


def test_dmz_host_is_asked_for_the_way_the_router_page_does():
    # On the real router dmzHost is not returned for ejGetVal, only for ejGetOtherVal.
    router = FakeRouter(replies=replies.canned())
    info.run({"gather_subset": ["security"]}, make(router))
    asked = [c[1] for c in router.calls if c[0] == "cgi_parameter_value.cmd"]
    assert {"action": "get", "ejGetVal": "enblUpnp,enblUpnpnat,fwLevel,fwStealthMode"} in asked
    assert {"action": "get", "ejGetOtherVal": "dmzHost"} in asked


def test_port_forwards_come_back_as_rules_from_the_routers_text_reply():
    canned = replies.canned()
    canned[("portForwardingAssociations.cmd", "readall")] = "TCP,192.0.2.50,8080,8080,0.0.0.0,80,80|UDP,192.0.2.51,53,53,198.51.100.7,5353,5353"
    router = FakeRouter(replies=canned)
    forwards = info.run({"gather_subset": ["security"]}, make(router))["exos"]["security"]["port_forwards"]
    assert forwards == [
        {"protocol": "tcp", "local_ip": "192.0.2.50", "local_port": 8080, "local_port_end": 8080,
         "remote_ip": None, "remote_port": 80, "remote_port_end": 80},
        {"protocol": "udp", "local_ip": "192.0.2.51", "local_port": 53, "local_port_end": 53,
         "remote_ip": "198.51.100.7", "remote_port": 5353, "remote_port_end": 5353},
    ]


# ---- every subset, against a router with all its settings

def everything():
    from ansible_collections.workshop144.calix_exos.tests.unit.fake_settings import client_for, settings_router, writes
    router = settings_router()
    router.state["chains"]["usv4"] = [{"name": "r1", "srcip": "", "dstip": "198.51.100.1", "proto": "tcpudp", "sport": "",
                                       "dport": "9", "action": "DROP"}]
    router.state["dns"] = [("printer.example", "192.0.2.50")]
    router.state["schedules"] = [("17000", "02:00:00:00:00:AA", "Mon,Sat", "22:00", "23:30")]
    router.state["svc_rules"] = {"games": ("1", ["tcp:9:9"])}
    router.state["svc_assocs"] = [("192.0.2.50", "games")]
    return router, info.run({"gather_subset": ["all"]}, client_for(router)), writes


def test_all_now_covers_every_setting_and_changes_nothing():
    router, result, writes = everything()
    exos = result["exos"]
    assert set(exos) == set(SUBSETS) and result["changed"] is False and writes(router) == []
    assert exos["firewall_rules"]["ipv4_out"] == [
        {"chain": "ipv4_out", "name": "r1", "source": None, "destination": "198.51.100.1", "protocol": "both",
         "source_port": None, "destination_port": "9", "action": "drop"},
    ]
    assert exos["firewall_rules"]["ipv6_in"] == []
    assert exos["dns_host_mappings"] == [{"hostname": "printer.example", "ip": "192.0.2.50"}]
    assert exos["arp_spoofing"] is False
    assert exos["controls"] == {"led": True, "brightness": 100, "sip_alg": False}
    assert exos["ipv6_lan"] == {"router_advertisement": True, "dhcpv6": True, "dhcpv6_mode": "both", "dns_servers": []}
    assert exos["access_schedules"] == [{"mac": "02:00:00:00:00:aa", "days": ["mon", "sat"], "start": "22:00", "end": "23:30"}]
    assert exos["service_blocking"] == {
        "rules": [{"name": "games", "custom": True, "ports": [{"protocol": "tcp", "port": 9, "port_end": 9}]}],
        "blocked": [{"ip": "192.0.2.50", "rule": "games"}]}
    assert exos["radios"][2] == {"band": "6", "enabled": True, "dfs": False, "mu_mimo": False, "psc_only": True,
                                 "wifi6": True, "wide_channels": True}
    assert exos["ports"] == [{"port": 1, "type": "Ethernet", "rate": "1000M", "connected": True},
                             {"port": 2, "type": "Ethernet", "rate": "Disconnected", "connected": False}]
    assert exos["internet"]["ipv4"] == {"device_ipv4_address": "198.51.100.20", "dns_address_1": "198.51.100.53"}
    assert exos["internet"]["status"] == {"ipv4_connection": "Connected"}
    assert exos["dhcp"]["lease_seconds"] == 43200 and exos["dhcp"]["dns_servers"] == []


def test_ddns_is_reported_without_its_password():
    router, result, writes = everything()
    assert result["exos"]["ddns"]["ipv4"] == {"enabled": True, "server": "dyndns.org", "user": "someone",
                                              "hostname": "home.example.org", "ip_source": "network", "website": None}
    assert result["exos"]["ddns"]["ipv6"]["enabled"] is False
    assert "c0ffee" not in repr(result) and "abab" not in repr(result)


def test_no_key_material_anywhere_in_everything():
    router, result, writes = everything()
    assert "correct horse" not in repr(result)
    assert "wlWpaPsk" not in repr(result) and "nonce" not in repr(result)
