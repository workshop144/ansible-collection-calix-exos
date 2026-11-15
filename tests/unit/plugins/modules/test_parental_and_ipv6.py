# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import pytest

from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError
from ansible_collections.workshop144.calix_exos.plugins.modules import (
    access_schedule,
    ipv6_lan,
    service_blocking,
    service_blocking_rule,
)
from ansible_collections.workshop144.calix_exos.tests.unit.fake_settings import client_for, settings_router, writes

MAC = "02:00:00:00:00:aa"


def go(module, router, check_mode=False, **params):
    return module.run(params, client_for(router), check_mode)


def no_sleep(seconds):
    return None


# ---------------------------------------------------------------- access_schedule

SCHED = dict(mac=MAC, days=["sat", "mon"], start="22:00", end="23:30", state="present")


def sched(**changes):
    merged = dict(SCHED)
    merged.update(changes)
    return merged


def test_schedule_add_sends_json_with_days_in_week_order_and_an_id():
    router = settings_router()
    result = go(access_schedule, router, **SCHED)
    endpoint, sent = writes(router)[0]
    assert endpoint == "detail_access.cmd" and "detail_access.cmd" in router.json_calls
    assert sent["action"] == "add" and sent["mac"] == MAC and sent["days"] == "Mon,Sat"
    assert sent["start_time"] == "22:00" and sent["end_time"] == "23:30" and sent["username"].isdigit()
    assert result["changed"] is True
    assert result["schedule"] == {"mac": MAC, "days": ["mon", "sat"], "start": "22:00", "end": "23:30"}


def test_schedule_same_is_no_change_whatever_the_order_or_case():
    router = settings_router(schedules=[("17000", MAC.upper(), "Mon,Sat", "22:00", "23:30")])
    assert go(access_schedule, router, **SCHED)["changed"] is False and writes(router) == []


def test_schedule_always_blocked_has_no_days_or_times():
    router = settings_router()
    result = go(access_schedule, router, **sched(days=None, start=None, end=None))
    sent = writes(router)[0][1]
    assert "days" not in sent and "start_time" not in sent
    assert result["schedule"] == {"mac": MAC, "days": [], "start": None, "end": None}


def test_schedule_absent_removes_by_the_routers_id():
    router = settings_router(schedules=[("17000", MAC, "Mon,Sat", "22:00", "23:30"), ("17001", MAC, "Sun", "01:00", "02:00")])
    result = go(access_schedule, router, **sched(state="absent"))
    assert writes(router) == [("detail_access.cmd", {"action": "remove", "username": "17000"})]
    assert result["schedule"] is None and len(router.state["schedules"]) == 1
    assert go(access_schedule, settings_router(), **sched(state="absent"))["changed"] is False


@pytest.mark.parametrize("bad", [dict(start="23:30", end="22:00"), dict(start="25:00"), dict(days=["funday"]),
                                 dict(start=None), dict(days=None), dict(mac="nope")])
def test_schedule_validation(bad):
    router = settings_router()
    with pytest.raises(ExosModuleError):
        go(access_schedule, router, **sched(**bad))
    assert router.calls == []


def test_schedule_refused_when_the_providers_app_runs_parental_controls():
    router = settings_router(schedule_type="ciq")
    with pytest.raises(ExosModuleError) as err:
        go(access_schedule, router, **SCHED)
    assert writes(router) == [] and "provider" in str(err.value)


def test_schedule_check_mode_and_readback():
    router = settings_router()
    assert go(access_schedule, router, check_mode=True, **SCHED)["changed"] is True
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(access_schedule, router, **SCHED)


# ---------------------------------------------------------------- service_blocking_rule

PORTS = [{"protocol": "tcp", "port": 9, "port_end": None}, {"protocol": "both", "port": 8000, "port_end": 8010}]


def test_service_rule_created_one_entry_per_request_with_wire_protocols():
    router = settings_router()
    result = go(service_blocking_rule, router, name="games", ports=PORTS, state="present")
    assert writes(router) == [
        ("serviceBlockingRule.cmd", {"action": "add", "ruleName": "games", "protocol": "tcp", "portStart": "9",
                                     "portEnd": "9", "isCustom": "1"}),
        ("serviceBlockingRule.cmd", {"action": "add", "ruleName": "games", "protocol": "tcpudp", "portStart": "8000",
                                     "portEnd": "8010", "isCustom": "1"}),
    ]
    assert result["changed"] is True
    assert result["rule"] == {"name": "games", "ports": [{"protocol": "tcp", "port": 9, "port_end": 9},
                                                         {"protocol": "both", "port": 8000, "port_end": 8010}]}


def test_service_rule_same_is_no_change_however_the_router_spells_the_protocol():
    router = settings_router(svc_rules={"games": ("1", ["TCP:9:9", "TCP/UDP:8000:8010"])})
    assert go(service_blocking_rule, router, name="games", ports=PORTS, state="present")["changed"] is False
    assert writes(router) == []


def test_service_rule_entries_added_and_removed_to_match():
    router = settings_router(svc_rules={"games": ("1", ["tcp:9:9", "udp:53:53"])})
    go(service_blocking_rule, router, name="games", ports=PORTS, state="present")
    assert [(w[1]["action"], w[1]["protocol"], w[1]["portStart"]) for w in writes(router)] == [
        ("add", "tcpudp", "8000"), ("remove", "udp", "53")]


def test_service_rule_absent_removes_every_entry():
    router = settings_router(svc_rules={"games": ("1", ["tcp:9:9", "udp:53:53"])})
    result = go(service_blocking_rule, router, name="games", ports=None, state="absent")
    assert [w[1]["action"] for w in writes(router)] == ["remove", "remove"]
    assert result["rule"] is None and router.state["svc_rules"] == {}


def test_service_rule_validation_and_built_in_rules():
    for bad in ("9games", "name with space", "x" * 15):
        with pytest.raises(ExosModuleError):
            go(service_blocking_rule, settings_router(), name=bad, ports=PORTS, state="present")
    with pytest.raises(ExosModuleError):
        go(service_blocking_rule, settings_router(), name="games", ports=[{"protocol": "tcp", "port": 90, "port_end": 80}],
           state="present")
    with pytest.raises(ExosModuleError):
        go(service_blocking_rule, settings_router(), name="games", ports=[], state="present")
    router = settings_router(svc_rules={"builtin": ("0", ["tcp:1:1"])})
    with pytest.raises(ExosModuleError):
        go(service_blocking_rule, router, name="builtin", ports=PORTS, state="present")
    assert writes(router) == []


def test_service_rule_check_mode_readback_and_provider_app():
    router = settings_router()
    assert go(service_blocking_rule, router, check_mode=True, name="games", ports=PORTS, state="present")["changed"]
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(service_blocking_rule, router, name="games", ports=PORTS, state="present")
    with pytest.raises(ExosModuleError):
        go(service_blocking_rule, settings_router(schedule_type="ciq"), name="games", ports=PORTS, state="present")


# ---------------------------------------------------------------- service_blocking

def blocked(router, check_mode=False, **params):
    return service_blocking.run(params, client_for(router), check_mode, sleep=no_sleep)


def test_service_blocking_associates_a_device_with_a_rule():
    router = settings_router(svc_rules={"games": ("1", ["tcp:9:9"])})
    result = blocked(router, ip="192.0.2.50", rule="games", state="present")
    assert writes(router) == [("serviceBlockingAssociation.cmd", {"action": "add", "ruleName": "games", "ipAddress": "192.0.2.50"})]
    assert result["changed"] is True and result["blocked"] == {"ip": "192.0.2.50", "rule": "games"}


def test_service_blocking_no_change_absent_and_unknown_rule():
    router = settings_router(svc_rules={"games": ("1", ["tcp:9:9"])}, svc_assocs=[("192.0.2.50", "games")])
    assert blocked(router, ip="192.0.2.50", rule="games", state="present")["changed"] is False
    result = blocked(router, ip="192.0.2.50", rule="games", state="absent")
    assert writes(router) == [("serviceBlockingAssociation.cmd", {"action": "remove", "ipAddress": "192.0.2.50", "ruleName": "games"})]
    assert result["blocked"] is None
    router = settings_router()
    with pytest.raises(ExosModuleError):
        blocked(router, ip="192.0.2.50", rule="nope", state="present")
    assert writes(router) == []


def test_service_blocking_address_must_be_on_the_lan():
    router = settings_router(svc_rules={"games": ("1", ["tcp:9:9"])})
    with pytest.raises(ExosModuleError):
        blocked(router, ip="198.51.100.9", rule="games", state="present")
    assert writes(router) == []


def test_service_blocking_check_mode_and_readback():
    router = settings_router(svc_rules={"games": ("1", ["tcp:9:9"])})
    assert blocked(router, check_mode=True, ip="192.0.2.50", rule="games", state="present")["changed"] is True
    assert writes(router) == []
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        blocked(router, ip="192.0.2.50", rule="games", state="present")


# ---------------------------------------------------------------- ipv6_lan

def test_ipv6_lan_no_change():
    router = settings_router()
    result = go(ipv6_lan, router, router_advertisement=True, dhcpv6=True, dhcpv6_mode="both", dns_servers=[])
    assert result["changed"] is False and writes(router) == []
    assert result["ipv6_lan"] == {"router_advertisement": True, "dhcpv6": True, "dhcpv6_mode": "both", "dns_servers": []}


def test_ipv6_lan_change_echoes_the_whole_setting_back():
    router = settings_router()
    go(ipv6_lan, router, router_advertisement=None, dhcpv6=None, dhcpv6_mode="stateless", dns_servers=None)
    endpoint, sent = writes(router)[0]
    assert endpoint == "lan_setting_ipv6.cmd" and endpoint in router.json_calls
    assert sent == {"action": "apply", "ra": "server", "dhcpv6": "server", "dhcpv6Mode": "stateless",
                    "dns6Type": "default", "somethingElse": "kept"}


def test_ipv6_lan_custom_dns_and_off():
    router = settings_router()
    result = go(ipv6_lan, router, router_advertisement=False, dhcpv6=None, dhcpv6_mode=None,
                dns_servers=["2001:db8::53", "2001:db8::54"])
    sent = writes(router)[0][1]
    assert sent["ra"] == "disabled" and sent["dns6Type"] == "custom"
    assert sent["advPriDns"] == "2001:db8::53" and sent["advSecDns"] == "2001:db8::54"
    assert result["ipv6_lan"]["dns_servers"] == ["2001:db8::53", "2001:db8::54"]


def test_ipv6_lan_validation_check_mode_readback():
    with pytest.raises(ExosModuleError):
        go(ipv6_lan, settings_router(), router_advertisement=None, dhcpv6=None, dhcpv6_mode=None, dns_servers=None)
    with pytest.raises(ExosModuleError):
        go(ipv6_lan, settings_router(), router_advertisement=None, dhcpv6=None, dhcpv6_mode=None, dns_servers=["192.0.2.1"])
    with pytest.raises(ExosModuleError):
        go(ipv6_lan, settings_router(), router_advertisement=None, dhcpv6=None, dhcpv6_mode=None,
           dns_servers=["2001:db8::1", "2001:db8::2", "2001:db8::3"])
    router = settings_router()
    assert go(ipv6_lan, router, check_mode=True, router_advertisement=False, dhcpv6=None, dhcpv6_mode=None, dns_servers=None)["changed"]
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(ipv6_lan, router, router_advertisement=False, dhcpv6=None, dhcpv6_mode=None, dns_servers=None)
