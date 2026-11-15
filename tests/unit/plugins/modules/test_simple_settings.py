# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import pytest

from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError
from ansible_collections.workshop144.calix_exos.plugins.modules import (
    arp_spoofing,
    controls,
    dmz,
    dns_host_mapping,
    port_forward,
    upnp,
)
from ansible_collections.workshop144.calix_exos.tests.unit.fake_settings import client_for, settings_router, writes


def go(module, router, check_mode=False, **params):
    return module.run(params, client_for(router), check_mode)


# ---------------------------------------------------------------- upnp

def test_upnp_already_off_is_no_change():
    router = settings_router()
    result = go(upnp, router, enabled=False, nat_t=None)
    assert result["changed"] is False and writes(router) == []
    assert result["upnp"] == {"enabled": False, "nat_t": False}


def test_upnp_on_sends_both_flags_and_reads_back():
    router = settings_router()
    result = go(upnp, router, enabled=True, nat_t=None)
    assert writes(router) == [("advanced_security_upnp.cgi", {"enblUpnp": "1", "enblUpnpnat": "1"})]
    assert result["changed"] is True
    assert result["diff"] == {"before": {"enabled": False, "nat_t": False}, "after": {"enabled": True, "nat_t": True}}


def test_upnp_nat_t_can_be_set_apart():
    router = settings_router()
    go(upnp, router, enabled=True, nat_t=False)
    assert writes(router)[0][1] == {"enblUpnp": "1", "enblUpnpnat": "0"}


def test_upnp_nat_t_without_upnp_is_refused():
    router = settings_router()
    with pytest.raises(ExosModuleError):
        go(upnp, router, enabled=False, nat_t=True)
    assert router.calls == []


def test_upnp_check_mode_sends_nothing():
    router = settings_router()
    assert go(upnp, router, check_mode=True, enabled=True, nat_t=None)["changed"] is True
    assert writes(router) == []


def test_upnp_readback_mismatch_fails():
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(upnp, router, enabled=True, nat_t=None)


def test_upnp_missing_setting_in_reply_fails():
    router = settings_router()
    del router.state["params"]["enblUpnp"]
    with pytest.raises(ExosError):
        go(upnp, router, enabled=False, nat_t=None)
    assert router.endpoints()[-1] == "logout.cgi"


# ---------------------------------------------------------------- dmz

def test_dmz_set_when_none():
    router = settings_router()
    result = go(dmz, router, dmz_host="192.0.2.50", state="present")
    assert writes(router) == [("scdmz.cmd", {"action": "add", "address": "192.0.2.50"})]
    assert result["changed"] is True and result["dmz_host"] == "192.0.2.50"


def test_dmz_same_is_no_change():
    router = settings_router(dmz="192.0.2.50")
    assert go(dmz, router, dmz_host="192.0.2.50", state="present")["changed"] is False
    assert writes(router) == []


def test_dmz_change_removes_the_old_host_first():
    router = settings_router(dmz="192.0.2.50")
    go(dmz, router, dmz_host="192.0.2.60", state="present")
    assert writes(router) == [
        ("scdmz.cmd", {"action": "remove", "address": "192.0.2.50"}),
        ("scdmz.cmd", {"action": "add", "address": "192.0.2.60"}),
    ]
    assert router.state["dmz"] == "192.0.2.60"


def test_dmz_absent_removes_whatever_is_set():
    router = settings_router(dmz="192.0.2.50")
    result = go(dmz, router, dmz_host=None, state="absent")
    assert writes(router) == [("scdmz.cmd", {"action": "remove", "address": "192.0.2.50"})]
    assert result["dmz_host"] is None


def test_dmz_absent_when_none_is_no_change():
    router = settings_router()
    assert go(dmz, router, dmz_host=None, state="absent")["changed"] is False


def test_dmz_check_mode_and_bad_address():
    router = settings_router()
    assert go(dmz, router, check_mode=True, dmz_host="192.0.2.50", state="present")["changed"] is True
    assert writes(router) == []
    with pytest.raises(ExosModuleError):
        go(dmz, settings_router(), dmz_host="not-an-ip", state="present")


def test_dmz_readback_mismatch_fails():
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(dmz, router, dmz_host="192.0.2.50", state="present")


# ---------------------------------------------------------------- port_forward

RULE = dict(protocol="tcp", local_ip="192.0.2.50", local_port=8080, local_port_end=None,
            remote_port=80, remote_port_end=None, remote_ip=None, state="present")
STORED = ["TCP", "192.0.2.50", "8080", "8080", "0.0.0.0", "80", "80"]


def rule(**changes):
    merged = dict(RULE)
    merged.update(changes)
    return merged


def test_port_forward_add():
    router = settings_router()
    result = go(port_forward, router, **RULE)
    assert writes(router) == [("advancedPortForwarding.cmd", {
        "action": "add", "protocol": "TCP", "localIpAddress": "192.0.2.50", "localPortStart": "8080",
        "localPortEnd": "8080", "remoteIpAddress": "", "remotePortStart": "80", "remotePortEnd": "80"})]
    assert result["changed"] is True
    assert result["rule"] == {"protocol": "tcp", "local_ip": "192.0.2.50", "local_port": 8080, "local_port_end": 8080,
                              "remote_ip": None, "remote_port": 80, "remote_port_end": 80}


def test_port_forward_same_is_no_change():
    router = settings_router(forwards=[list(STORED)])
    assert go(port_forward, router, **RULE)["changed"] is False
    assert writes(router) == []


def test_port_forward_remote_port_defaults_to_local_port():
    router = settings_router()
    result = go(port_forward, router, **rule(remote_port=None))
    assert result["rule"]["remote_port"] == 8080


def test_port_forward_same_outside_port_other_target_is_replaced():
    router = settings_router(forwards=[list(STORED)])
    go(port_forward, router, **rule(local_ip="192.0.2.60"))
    assert [w[1]["action"] for w in writes(router)] == ["remove", "add"]
    assert writes(router)[0][1]["remoteIpAddress"] == "0.0.0.0"   # removal sends the address as it was read
    assert router.state["forwards"] == [["TCP", "192.0.2.60", "8080", "8080", "0.0.0.0", "80", "80"]]


def test_port_forward_absent_removes_by_outside_port_and_protocol():
    router = settings_router(forwards=[list(STORED)])
    result = go(port_forward, router, **rule(state="absent", local_ip=None, local_port=None))
    assert router.state["forwards"] == [] and result["changed"] is True and result["rule"] is None


def test_port_forward_absent_missing_is_no_change():
    assert go(port_forward, settings_router(), **rule(state="absent"))["changed"] is False


def test_port_forward_range_widths_must_match():
    with pytest.raises(ExosModuleError):
        go(port_forward, settings_router(), **rule(local_port_end=8090, remote_port_end=85))


@pytest.mark.parametrize("remote_port,protocol", [(60050, "udp"), (8443, "tcp"), (30006, "both")])
def test_port_forward_refuses_ports_the_router_reserves(remote_port, protocol):
    router = settings_router()
    with pytest.raises(ExosModuleError):
        go(port_forward, router, **rule(remote_port=remote_port, protocol=protocol))
    assert router.calls == []


def test_port_forward_both_protocols_and_a_source_address():
    router = settings_router()
    go(port_forward, router, **rule(protocol="both", remote_ip="198.51.100.7"))
    sent = writes(router)[0][1]
    assert sent["protocol"] == "TCP/UDP" and sent["remoteIpAddress"] == "198.51.100.7"


def test_port_forward_check_mode_and_readback():
    router = settings_router()
    assert go(port_forward, router, check_mode=True, **RULE)["changed"] is True
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(port_forward, router, **RULE)


def test_port_forward_bad_record_from_router_fails():
    router = settings_router()
    router.handlers["portForwardingAssociations.cmd"] = lambda r, a, p: "TCP,192.0.2.5,80"
    with pytest.raises(ExosError):
        go(port_forward, router, **RULE)


# ---------------------------------------------------------------- dns_host_mapping

def test_dns_mapping_add():
    router = settings_router()
    result = go(dns_host_mapping, router, hostname="printer.example", ip="192.0.2.50", state="present")
    assert writes(router) == [("dns_host_mapping.cmd", {"action": "add", "hostName": "printer.example", "ip": "192.0.2.50"})]
    assert result["changed"] is True and result["mapping"] == {"hostname": "printer.example", "ip": "192.0.2.50"}


def test_dns_mapping_same_is_no_change_whatever_the_case():
    router = settings_router(dns=[("printer.example", "192.0.2.50")])
    assert go(dns_host_mapping, router, hostname="Printer.Example", ip="192.0.2.50", state="present")["changed"] is False


def test_dns_mapping_other_address_is_replaced():
    router = settings_router(dns=[("printer.example", "192.0.2.50")])
    go(dns_host_mapping, router, hostname="printer.example", ip="192.0.2.60", state="present")
    assert [w[1]["action"] for w in writes(router)] == ["del", "add"]
    assert router.state["dns"] == [("printer.example", "192.0.2.60")]


def test_dns_mapping_absent():
    router = settings_router(dns=[("printer.example", "192.0.2.50")])
    result = go(dns_host_mapping, router, hostname="printer.example", ip=None, state="absent")
    assert writes(router) == [("dns_host_mapping.cmd", {"action": "del", "hostName": "printer.example", "ip": "192.0.2.50"})]
    assert result["mapping"] is None


def test_dns_mapping_validation():
    for bad in ("-bad", "has space", "a" * 64, "1234"):
        router = settings_router()
        with pytest.raises(ExosModuleError):
            go(dns_host_mapping, router, hostname=bad, ip="192.0.2.50", state="present")
        assert router.calls == []
    router = settings_router()
    with pytest.raises(ExosModuleError):   # the router's own address cannot be mapped
        go(dns_host_mapping, router, hostname="x.example", ip="192.0.2.1", state="present")
    assert writes(router) == []


def test_dns_mapping_check_mode_and_readback():
    router = settings_router()
    assert go(dns_host_mapping, router, check_mode=True, hostname="a.example", ip="192.0.2.9", state="present")["changed"]
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(dns_host_mapping, router, hostname="a.example", ip="192.0.2.9", state="present")


# ---------------------------------------------------------------- arp_spoofing

def test_arp_spoofing_on_sends_json_string_flag():
    router = settings_router()
    result = go(arp_spoofing, router, enabled=True)
    assert writes(router) == [("arp_spoof.cmd", {"action": "set", "admin": "1"})]
    assert "arp_spoof.cmd" in router.json_calls
    assert result["changed"] is True and result["enabled"] is True


def test_arp_spoofing_no_change_check_mode_readback():
    assert go(arp_spoofing, settings_router(), enabled=False)["changed"] is False
    router = settings_router()
    assert go(arp_spoofing, router, check_mode=True, enabled=True)["changed"] is True
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(arp_spoofing, router, enabled=True)


# ---------------------------------------------------------------- controls

def test_controls_no_change():
    router = settings_router()
    result = go(controls, router, led=True, brightness=100, sip_alg=False)
    assert result["changed"] is False and writes(router) == []
    assert result["controls"] == {"led": True, "brightness": 100, "sip_alg": False}


def test_controls_sip_alg_is_its_own_request_with_a_number():
    router = settings_router()
    go(controls, router, led=None, brightness=None, sip_alg=True)
    assert writes(router) == [("advanced_controls.cmd", {"action": "set", "sip": 1})]


def test_controls_led_off_sends_no_brightness():
    router = settings_router()
    go(controls, router, led=False, brightness=None, sip_alg=None)
    assert writes(router) == [("advanced_controls.cmd", {"action": "set", "led": 0})]


def test_controls_brightness_change_keeps_led_on():
    router = settings_router()
    result = go(controls, router, led=None, brightness=50, sip_alg=None)
    assert writes(router) == [("advanced_controls.cmd", {"action": "set", "led": 1, "brightness": 50})]
    assert result["controls"]["brightness"] == 50


def test_controls_validation():
    with pytest.raises(ExosModuleError):
        go(controls, settings_router(), led=None, brightness=55, sip_alg=None)
    with pytest.raises(ExosModuleError):
        go(controls, settings_router(), led=None, brightness=None, sip_alg=None)
    router = settings_router()
    router.state["controls"]["brightness_supported"] = 0
    with pytest.raises(ExosModuleError):
        go(controls, router, led=None, brightness=50, sip_alg=None)
    assert writes(router) == []


def test_controls_check_mode_and_readback():
    router = settings_router()
    assert go(controls, router, check_mode=True, led=False, brightness=None, sip_alg=True)["changed"] is True
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(controls, router, led=False, brightness=None, sip_alg=None)
