# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import pytest

from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError
from ansible_collections.workshop144.calix_exos.plugins.module_utils.firewall_table import SERVICES, firewall_info
from ansible_collections.workshop144.calix_exos.plugins.modules import backup, device, firewall, firewall_rule, ping, traceroute
from ansible_collections.workshop144.calix_exos.tests.unit.fake_settings import client_for, settings_router, writes


def go(module, router, check_mode=False, **params):
    return module.run(params, client_for(router), check_mode)


# ---------------------------------------------------------------- firewall table

def test_firewall_info_lists_every_service_both_ways_in_the_pages_order():
    info = firewall_info("High").split("|")
    assert len(info) == 2 * len(SERVICES) == 104
    assert info[0] == "directx_in:1" and info[1] == "directx_out:0"
    assert info[-2] == "all_other_ports_in:1" and info[-1] == "all_other_ports_out:0"
    assert set(part.rsplit(":", 1)[1] for part in firewall_info("Basic").split("|")) == {"0"}


# ---------------------------------------------------------------- firewall

def test_firewall_no_change():
    router = settings_router()
    result = go(firewall, router, level="high", stealth_mode=True)
    assert result["changed"] is False and writes(router) == []
    assert result["firewall"] == {"level": "high", "stealth_mode": True}


def test_firewall_level_change_sends_the_whole_table_for_that_level():
    router = settings_router()
    result = go(firewall, router, level="medium", stealth_mode=None)
    sent = writes(router)[0]
    assert sent[0] == "advanced_firewallsettings.cmd"
    assert sent[1]["fwLevel"] == "Medium" and sent[1]["fwStealthMode"] == "1"
    assert sent[1]["currentPage"] == "advanced_security_firewallsettings.html"
    assert sent[1]["firewallInfo"] == firewall_info("Medium")
    assert "sessionKey" not in sent[1]
    assert result["changed"] is True and result["firewall"] == {"level": "medium", "stealth_mode": True}


def test_firewall_sends_the_session_key_when_the_router_gives_one():
    router = settings_router()
    router.state["params"]["sessionKey"] = "12345"
    go(firewall, router, level="low", stealth_mode=None)
    assert writes(router)[0][1]["sessionKey"] == "12345"


def test_firewall_stealth_only_keeps_the_level():
    router = settings_router()
    go(firewall, router, level=None, stealth_mode=False)
    sent = writes(router)[0][1]
    assert sent["fwLevel"] == "High" and sent["fwStealthMode"] == "0" and sent["firewallInfo"] == firewall_info("High")


def test_firewall_off_is_the_routers_basic_level():
    router = settings_router()
    assert go(firewall, router, level="off", stealth_mode=None)["firewall"]["level"] == "off"
    assert router.state["params"]["fwLevel"] == "Basic"


def test_firewall_needs_an_option_check_mode_readback_unknown_level():
    with pytest.raises(ExosModuleError):
        go(firewall, settings_router(), level=None, stealth_mode=None)
    router = settings_router()
    assert go(firewall, router, check_mode=True, level="low", stealth_mode=None)["changed"] is True
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(firewall, router, level="low", stealth_mode=None)
    router = settings_router()
    router.state["params"]["fwLevel"] = "Paranoid"
    with pytest.raises(ExosError):
        go(firewall, router, level="low", stealth_mode=None)


# ---------------------------------------------------------------- firewall_rule

RULE = dict(chain="ipv4_out", name="block-test", source=None, destination="198.51.100.1", protocol="tcp",
            source_port=None, destination_port="9", action="drop", state="present")
WIRE = {"name": "block-test", "srcip": "", "dstip": "198.51.100.1", "proto": "tcp", "sport": "", "dport": "9", "action": "DROP"}


def frule(**changes):
    merged = dict(RULE)
    merged.update(changes)
    return merged


def test_firewall_rule_added_at_the_end_of_its_chain():
    other = dict(WIRE, name="first", dport="10")
    router = settings_router()
    router.state["chains"]["usv4"] = [other]
    result = go(firewall_rule, router, **RULE)
    assert writes(router) == [("advfw_apply.cmd", {"usv4": [other, WIRE]})]
    assert "advfw_apply.cmd" in router.json_calls
    assert result["changed"] is True
    assert result["rule"] == {"chain": "ipv4_out", "name": "block-test", "source": None, "destination": "198.51.100.1",
                              "protocol": "tcp", "source_port": None, "destination_port": "9", "action": "drop"}


def test_firewall_rule_same_is_no_change():
    router = settings_router()
    router.state["chains"]["usv4"] = [dict(WIRE)]
    assert go(firewall_rule, router, **RULE)["changed"] is False and writes(router) == []


def test_firewall_rule_change_keeps_its_place_and_unknown_keys():
    first, last = dict(WIRE, name="first"), dict(WIRE, name="last")
    router = settings_router()
    router.state["chains"]["usv4"] = [first, dict(WIRE, extra="kept"), last]
    go(firewall_rule, router, **frule(action="accept", destination_port="8000:8100"))
    sent = writes(router)[0][1]["usv4"]
    assert [r["name"] for r in sent] == ["first", "block-test", "last"]
    assert sent[1] == dict(WIRE, action="ACCEPT", dport="8000:8100", extra="kept")


def test_firewall_rule_absent():
    router = settings_router()
    router.state["chains"]["usv4"] = [dict(WIRE)]
    result = go(firewall_rule, router, **frule(state="absent"))
    assert writes(router) == [("advfw_apply.cmd", {"usv4": []})]
    assert result["rule"] is None
    assert go(firewall_rule, settings_router(), **frule(state="absent"))["changed"] is False


def test_firewall_rule_both_protocols_and_chain_names():
    router = settings_router()
    go(firewall_rule, router, **frule(chain="ipv6_in", protocol="both", destination="2001:db8::/32"))
    sent = writes(router)[0][1]
    assert list(sent) == ["dsv6"] and sent["dsv6"][0]["proto"] == "tcpudp"


@pytest.mark.parametrize("bad", [
    dict(name="has space"), dict(name="x" * 33), dict(destination="2001:db8::1"), dict(destination="10.0.0.0/33"),
    dict(destination_port="70000"), dict(destination_port="90:80"), dict(source_port="http"),
])
def test_firewall_rule_validation(bad):
    router = settings_router()
    with pytest.raises(ExosModuleError):
        go(firewall_rule, router, **frule(**bad))
    assert router.calls == []


def test_firewall_rule_chain_limit_check_mode_readback():
    router = settings_router()
    router.state["chains"]["usv4"] = [dict(WIRE, name="r%d" % i) for i in range(64)]
    with pytest.raises(ExosModuleError):
        go(firewall_rule, router, **RULE)
    router = settings_router()
    assert go(firewall_rule, router, check_mode=True, **RULE)["changed"] is True
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(firewall_rule, router, **RULE)


def test_firewall_rule_bad_chain_reply_fails():
    router = settings_router()
    router.handlers["advfw_load.cmd"] = lambda r, a, p: ""
    with pytest.raises(ExosError):
        go(firewall_rule, router, **RULE)
    assert writes(router) == []


# ---------------------------------------------------------------- device

def test_device_rename():
    router = settings_router()
    result = go(device, router, mac="02-00-00-00-00-AA", name="office printer", type=None)
    assert writes(router) == [("device_table.cmd", {"action": "set", "version": "ipv4", "mac": "02:00:00:00:00:aa",
                                                    "type": "Printer", "deviceName": "office printer"})]
    assert result["changed"] is True
    assert result["device"] == {"mac": "02:00:00:00:00:aa", "name": "office printer", "type": "Printer"}


def test_device_no_change_type_change_unknown_mac():
    assert go(device, settings_router(), mac="02:00:00:00:00:aa", name="printer", type="Printer")["changed"] is False
    router = settings_router()
    go(device, router, mac="02:00:00:00:00:aa", name=None, type="TV")
    assert writes(router)[0][1]["type"] == "TV" and writes(router)[0][1]["deviceName"] == "printer"
    router = settings_router()
    with pytest.raises(ExosModuleError):
        go(device, router, mac="02:00:00:00:00:bb", name="x", type=None)
    assert writes(router) == []


def test_device_validation_check_mode_readback():
    with pytest.raises(ExosModuleError):
        go(device, settings_router(), mac="02:00:00:00:00:aa", name=None, type=None)
    with pytest.raises(ExosModuleError):
        go(device, settings_router(), mac="02:00:00:00:00:aa", name="n" * 64, type=None)
    router = settings_router()
    assert go(device, router, check_mode=True, mac="02:00:00:00:00:aa", name="new", type=None)["changed"] is True
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(device, router, mac="02:00:00:00:00:aa", name="new", type=None)


# ---------------------------------------------------------------- ping / traceroute

def no_sleep(seconds):
    return None


def test_ping_starts_waits_and_reports():
    router = settings_router()
    result = ping.run({"target": "192.0.2.9", "packet_size": 32, "source_ip": None, "ip_version": "ipv4", "wait": 30},
                      client_for(router), False, sleep=no_sleep)
    start = [c for c in router.calls if c[1].get("action") == "start_ping"][0][1]
    assert start == {"action": "start_ping", "version": "ipv4", "ip_addr": "192.0.2.9", "packet_size": "32", "source_ip": ""}
    assert result["changed"] is False and result["reachable"] is True
    assert result["ping"] == {"target": "192.0.2.9", "sent": 4, "received": 4, "loss_percent": 0.0,
                              "min_ms": 0.9, "max_ms": 1.2, "avg_ms": 1.0,
                              "replies": [{"from": "192.0.2.9", "bytes": 40, "time_ms": 1.2, "ttl": 64},
                                          {"from": "192.0.2.9", "bytes": 40, "time_ms": 0.9, "ttl": 64}]}


def test_ping_unreachable_is_reported_not_failed():
    router = settings_router()
    router.state["ping"]["final"] = {
        "status": 2, "result": [],
        "statistic": {"sent": 4, "receive": 0, "loss": "100%", "min": "--ms", "max": "--ms", "avg": "--ms"},
    }
    result = ping.run({"target": "192.0.2.9", "packet_size": 32, "source_ip": None, "ip_version": "ipv4", "wait": 30},
                      client_for(router), False, sleep=no_sleep)
    assert result["reachable"] is False and result["ping"]["loss_percent"] == 100.0 and result["ping"]["avg_ms"] is None


def test_ping_router_error_text_and_timeout_and_busy():
    router = settings_router()
    router.state["ping"]["final"] = {"status": 2, "msg": "ping: bad address 'nope'"}
    with pytest.raises(ExosModuleError) as err:
        ping.run({"target": "nope", "packet_size": 32, "source_ip": None, "ip_version": "ipv4", "wait": 30},
                 client_for(router), False, sleep=no_sleep)
    assert "bad address" in str(err.value)
    router = settings_router()
    router.state["ping"]["final"] = {"status": 1}
    with pytest.raises(ExosModuleError):
        ping.run({"target": "192.0.2.9", "packet_size": 32, "source_ip": None, "ip_version": "ipv4", "wait": 5},
                 client_for(router), False, sleep=no_sleep)
    router = settings_router()
    router.state["ping"]["busy"] = True
    with pytest.raises(ExosError) as err:
        ping.run({"target": "192.0.2.9", "packet_size": 32, "source_ip": None, "ip_version": "ipv4", "wait": 5},
                 client_for(router), False, sleep=no_sleep)
    assert err.value.code == "049"


def test_traceroute_starts_waits_and_reports():
    router = settings_router()
    result = traceroute.run({"target": "192.0.2.9", "mode": "icmp", "reverse_dns": False, "ip_version": "ipv4", "wait": 60},
                            client_for(router), False, sleep=no_sleep)
    start = [c for c in router.calls if c[1].get("action") == "trace"][0][1]
    assert start == {"action": "trace", "ip_addr": "192.0.2.9", "mode": "icmp", "reverse_dns": "disabled", "version": "ipv4"}
    assert result["changed"] is False
    assert result["hops"] == [{"hop": "1  192.0.2.1", "times": ["0.5 ms", "0.4 ms", "0.4 ms"]},
                              {"hop": "2  192.0.2.9", "times": ["1.5 ms", "1.4 ms", "1.4 ms"]}]


def test_traceroute_timeout_cancels():
    router = settings_router()
    router.state["trace"]["final"] = {"status": 1, "trace": []}
    with pytest.raises(ExosModuleError):
        traceroute.run({"target": "192.0.2.9", "mode": "udp", "reverse_dns": True, "ip_version": "ipv4", "wait": 5},
                       client_for(router), False, sleep=no_sleep)
    assert router.state["trace"].get("cancelled") is True


# ---------------------------------------------------------------- backup

HEADER = b'<!--CalixVersion="0.0.0.0" crc32="0badf00d" type="backup" fsan="CXNK00000000" product="1" ConfigVersion="25.4.0.0.57" model="GS4227W" -->'


def test_backup_writes_the_file_private_and_reports_its_header(tmp_path):
    router = settings_router()
    router.files["backupsettings.conf"] = HEADER + b"\x00\x01opaque"
    dest = tmp_path / "router.conf"
    result = go(backup, router, dest=str(dest))
    assert dest.read_bytes() == HEADER + b"\x00\x01opaque"
    assert oct(dest.stat().st_mode & 0o777) == "0o600"
    assert result["changed"] is True
    assert result["backup"] == {"dest": str(dest), "size": len(HEADER) + 8, "model": "GS4227W",
                                "config_version": "25.4.0.0.57", "crc32": "0badf00d"}


def test_backup_same_content_is_no_change_and_check_mode_writes_nothing(tmp_path):
    router = settings_router()
    router.files["backupsettings.conf"] = HEADER + b"x"
    dest = tmp_path / "router.conf"
    go(backup, router, dest=str(dest))
    assert go(backup, router, dest=str(dest))["changed"] is False
    other = tmp_path / "other.conf"
    assert go(backup, router, check_mode=True, dest=str(other))["changed"] is True
    assert not other.exists()


def test_backup_that_is_not_a_backup_fails_and_writes_nothing(tmp_path):
    router = settings_router()
    dest = tmp_path / "router.conf"
    with pytest.raises(ExosError):          # no such file on the router: it answers with its login page
        go(backup, router, dest=str(dest))
    router.files["backupsettings.conf"] = b"something else entirely"
    with pytest.raises(ExosModuleError):
        go(backup, router, dest=str(dest))
    assert not dest.exists()
