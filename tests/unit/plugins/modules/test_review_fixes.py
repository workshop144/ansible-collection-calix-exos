# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Behaviour pinned after the review of 0.2.0: failure paths the first tests did not reach."""

from __future__ import annotations

from urllib.error import HTTPError

import pytest

from ansible_collections.workshop144.calix_exos.plugins.module_utils import settings
from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError
from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosError
from ansible_collections.workshop144.calix_exos.plugins.modules import (
    backup,
    device,
    dhcp,
    dmz,
    dns_host_mapping,
    ipv6_lan,
    port_forward,
    reboot,
    service_blocking_rule,
    upnp,
    wifi_network,
    wifi_secondary_network,
)
from ansible_collections.workshop144.calix_exos.tests.unit.fake_settings import client_for, settings_router, writes


def no_sleep(seconds):
    return None


def go(module, router, check_mode=False, **params):
    return module.run(params, client_for(router), check_mode)


def wgo(module, router, check_mode=False, **params):
    return module.run(params, client_for(router), check_mode, sleep=no_sleep)


# ---------------------------------------------------------------- reboot

BOOT = {"wait": True, "timeout": 600, "settle": 80}


def test_reboot_http_error_on_the_request_is_a_failure_not_a_restart():
    router = settings_router()
    router.fail_next("rebootinfo.cgi", None, HTTPError("u", 404, "Not Found", {}, None))
    with pytest.raises(ExosError):
        reboot.run(dict(BOOT), client_for(router), False, sleep=no_sleep)
    assert "rebooted" not in router.state
    assert router.endpoints()[-1] == "logout.cgi"


def test_reboot_that_the_router_ignored_is_reported_as_not_restarted():
    router = settings_router(reboot_ignored=True)
    with pytest.raises(ExosModuleError) as err:
        reboot.run(dict(BOOT), client_for(router), False, sleep=no_sleep)
    assert "did not restart" in str(err.value)


def test_reboot_error_reply_logs_out():
    router = settings_router()
    router.fail_next("rebootinfo.cgi", None, "#ERROR_019")
    with pytest.raises(ExosError):
        reboot.run(dict(BOOT), client_for(router), False, sleep=no_sleep)
    assert router.endpoints()[-1] == "logout.cgi"


def test_reboot_confirms_by_the_uptime_and_logs_out_afterwards():
    router = settings_router()
    result = reboot.run(dict(BOOT), client_for(router), False, sleep=no_sleep)
    assert result["rebooted"] is True and result["uptime_seconds"] == 90
    assert router.endpoints()[-1] == "logout.cgi"


def test_reboot_connection_dropped_by_the_request_is_the_restart_starting():
    router = settings_router()
    original = router.handlers["rebootinfo.cgi"]

    def drop(r, action, params):
        original(r, action, params)
        raise ConnectionResetError()
    router.handlers["rebootinfo.cgi"] = drop
    assert reboot.run(dict(BOOT), client_for(router), False, sleep=no_sleep)["rebooted"] is True


# ---------------------------------------------------------------- remove-then-add puts the old entry back

def test_dmz_replace_restores_the_old_host_when_the_new_one_is_refused():
    router = settings_router(dmz="192.0.2.50")
    router.fail_next("scdmz.cmd", "remove", None)
    router.fail_next("scdmz.cmd", "add", "#ERROR_019")
    with pytest.raises(ExosModuleError) as err:
        go(dmz, router, dmz_host="192.0.2.60", state="present")
    assert router.state["dmz"] == "192.0.2.50" and "restored" in str(err.value)


def test_dmz_replace_says_so_when_nothing_could_be_restored():
    router = settings_router(dmz="192.0.2.50")
    router.fail_next("scdmz.cmd", "add", "#ERROR_019")
    router.fail_next("scdmz.cmd", "add", "#ERROR_019")
    with pytest.raises(ExosModuleError) as err:
        go(dmz, router, dmz_host="192.0.2.60", state="present")
    assert router.state["dmz"] is None and "no DMZ host" in str(err.value)


def test_port_forward_replace_restores_the_old_rule_when_the_new_one_is_refused():
    old = ["TCP", "192.0.2.50", "8080", "8080", "0.0.0.0", "80", "80"]
    router = settings_router(forwards=[list(old)])
    router.fail_next("advancedPortForwarding.cmd", "add", "#ERROR_546")
    with pytest.raises(ExosModuleError) as err:
        go(port_forward, router, protocol="tcp", local_ip="192.0.2.60", local_port=8080, local_port_end=None,
           remote_port=80, remote_port_end=None, remote_ip=None, state="present")
    assert router.state["forwards"] == [old] and "restored" in str(err.value)


def test_dns_mapping_replace_restores_the_old_address_when_the_new_one_is_refused():
    router = settings_router(dns=[("printer.example", "192.0.2.50")])
    router.fail_next("dns_host_mapping.cmd", "add", "#ERROR_060")
    with pytest.raises(ExosModuleError) as err:
        go(dns_host_mapping, router, hostname="printer.example", ip="192.0.2.60", state="present")
    assert router.state["dns"] == [("printer.example", "192.0.2.50")] and "restored" in str(err.value)


def test_service_rule_in_use_is_not_removed_piece_by_piece():
    router = settings_router(svc_rules={"games": ("1", ["tcp:9:9", "udp:53:53"])}, svc_assocs=[("192.0.2.50", "games")])
    with pytest.raises(ExosModuleError) as err:
        go(service_blocking_rule, router, name="games", ports=None, state="absent")
    assert writes(router) == [] and "192.0.2.50" in str(err.value)


# ---------------------------------------------------------------- secondary network: nothing changes unasked

NET = dict(ssid="guests", kind=None, band=None, security=None, key=None, isolation=None, state="present")


def net(**changes):
    merged = dict(NET)
    merged.update(changes)
    return merged


def make_guest(router, security="wpa2"):
    wgo(wifi_secondary_network, router, **net(security=security, key="eight chars or more"))
    return len(writes(router))


def test_secondary_isolation_only_keeps_the_security_it_has():
    router = settings_router()
    make_guest(router, "wpa2")
    result = wgo(wifi_secondary_network, router, **net(isolation=False))
    row = router.state["wifi"]["secondary"][0]
    assert row["row"]["wlAuthMode"] == "psk2" and row["row"]["wlSubnet"] == 0 and row["key"] == "eight chars or more"
    assert result["network"]["security"] == "wpa2"


def test_secondary_created_without_a_security_gets_the_default():
    router = settings_router()
    wgo(wifi_secondary_network, router, **net(key="eight chars or more"))
    assert router.state["wifi"]["secondary"][0]["row"]["wlAuthMode"] == "wpa3-mixed"


def test_secondary_naming_another_kind_than_it_is_fails():
    router = settings_router()
    wgo(wifi_secondary_network, router, **net(kind="custom", band="5", security="wpa2", key="eight chars or more"))
    before = len(writes(router))
    with pytest.raises(ExosModuleError):
        wgo(wifi_secondary_network, router, **net(kind="guest"))
    assert len(writes(router)) == before
    assert wgo(wifi_secondary_network, router, **net())["changed"] is False       # kind not named: left as it is


def test_secondary_absent_does_not_judge_the_key():
    router = settings_router()
    make_guest(router)
    assert wgo(wifi_secondary_network, router, **net(state="absent", key="short"))["changed"] is True


def test_secondary_row_without_isolation_state_fails_instead_of_reading_as_off():
    router = settings_router()
    make_guest(router)
    del router.state["wifi"]["secondary"][0]["row"]["wlSubnet"]
    count = len(writes(router))
    with pytest.raises(ExosError):
        wgo(wifi_secondary_network, router, **net(key="another key entirely"))
    assert len(writes(router)) == count


def test_secondary_undecryptable_held_key_is_not_sent_back():
    router = settings_router()
    make_guest(router)
    count = len(writes(router))
    original = router.handlers["wlinfo.cmd"]

    def garbled(r, action, params):
        rows = original(r, action, params)
        if action == "get_ssid_setup" and params.get("wlSsidUsage") == "guest":
            rows[0]["wlWpaPsk"] = "0102"      # decrypts to something that is not a key
        return rows
    router.handlers["wlinfo.cmd"] = garbled
    with pytest.raises(ExosModuleError):
        wgo(wifi_secondary_network, router, **net(isolation=False))
    assert len(writes(router)) == count


# ---------------------------------------------------------------- primary network

def test_primary_row_without_hidden_state_fails_instead_of_reading_as_shown():
    router = settings_router()
    original = router.handlers["wlinfo.cmd"]

    def no_hidden(r, action, params):
        rows = original(r, action, params)
        if action == "get_ssid_setup" and params.get("wlSsidUsage") == "primary":
            for row in rows:
                del row["wlHidden"]
        return rows
    router.handlers["wlinfo.cmd"] = no_hidden
    with pytest.raises(ExosError):
        wgo(wifi_network, router, ssid=None, security=None, key="a brand new key", hidden=None)
    assert writes(router) == []


def test_primary_undecryptable_held_key_is_not_sent_back():
    router = settings_router()
    original = router.handlers["wlinfo.cmd"]

    def garbled(r, action, params):
        rows = original(r, action, params)
        if action == "get_ssid_setup":
            for row in rows:
                row["wlWpaPsk"] = "0102"
        return rows
    router.handlers["wlinfo.cmd"] = garbled
    with pytest.raises(ExosModuleError):
        wgo(wifi_network, router, ssid=None, security=None, key=None, hidden=True)
    assert writes(router) == []


# ---------------------------------------------------------------- unknown spellings are not "off"

def test_unknown_flag_spelling_fails():
    router = settings_router()
    router.state["params"]["enblUpnp"] = ""
    with pytest.raises(ExosError):
        go(upnp, router, enabled=False, nat_t=None)
    router = settings_router()
    router.state["params"]["enblDhcpSrv"] = "maybe"
    with pytest.raises(ExosError):
        wgo(dhcp, router, enabled=None, pool_start=None, pool_end=None, lease_seconds=3600, dns_servers=None,
            lan_address=None, lan_netmask=None, hostname=None, domain=None, force=False)
    assert writes(router) == []


def test_ipv6_lan_unknown_mode_word_fails_and_a_dns_change_leaves_the_rest_as_sent():
    router = settings_router()
    router.state["ipv6_lan"]["ra"] = "relay"
    with pytest.raises(ExosError):
        go(ipv6_lan, router, router_advertisement=None, dhcpv6=None, dhcpv6_mode=None, dns_servers=["2001:db8::53"])
    assert writes(router) == []
    router = settings_router()
    go(ipv6_lan, router, router_advertisement=None, dhcpv6=None, dhcpv6_mode=None, dns_servers=["2001:db8::53"])
    sent = writes(router)[0][1]
    assert sent["ra"] == "server" and sent["dhcpv6"] == "server" and sent["dhcpv6Mode"] == "both"


def test_dmz_value_without_a_host_part_is_none():
    assert settings.parse_dmz("0") is None and settings.parse_dmz("") is None and settings.parse_dmz("0|") is None
    assert settings.parse_dmz("1|192.0.2.5") == "192.0.2.5"


# ---------------------------------------------------------------- dhcp

DHCP = dict(enabled=None, pool_start=None, pool_end=None, lease_seconds=None, dns_servers=None, lan_address=None,
            lan_netmask=None, hostname=None, domain=None, force=False)


def dh(**changes):
    merged = dict(DHCP)
    merged.update(changes)
    return merged


def test_dhcp_pool_settings_while_it_is_off_are_refused_up_front():
    router = settings_router()
    router.state["params"]["enblDhcpSrv"] = "0"
    with pytest.raises(ExosModuleError) as err:
        wgo(dhcp, router, **dh(lease_seconds=3600))
    assert writes(router) == [] and "enabled" in str(err.value)


def test_dhcp_turned_on_with_no_pool_known_fails_cleanly():
    router = settings_router()
    router.state["params"].update(enblDhcpSrv="0", dhcpEthStart="", dhcpEthEnd="")
    with pytest.raises(ExosModuleError):
        wgo(dhcp, router, **dh(enabled=True))
    assert writes(router) == []


@pytest.mark.parametrize("bad", [
    dict(dns_servers=["0.0.0.0"]),
    dict(lan_netmask="0.0.0.255", force=True),
    dict(lan_address="198.51.100.1", pool_start="198.51.100.100", pool_end="198.51.100.200", force=True),
    dict(lan_address="192.168.13.1", pool_start="192.168.13.100", pool_end="192.168.13.200", force=True),
])
def test_dhcp_more_validation(bad):
    router = settings_router()
    with pytest.raises(ExosModuleError):
        wgo(dhcp, router, **dh(**bad))
    assert writes(router) == []


# ---------------------------------------------------------------- smaller things

def test_unparsable_wifi_reply_is_not_quoted_in_the_error():
    router = settings_router()
    router.handlers["wlinfo.cmd"] = lambda r, action, params: '[{"nonce": "feedface", "wlWpaPsk": "c0ffee"'
    with pytest.raises(ExosError) as err:
        wgo(wifi_network, router, ssid=None, security=None, key=None, hidden=True)
    assert "feedface" not in str(err.value) and "c0ffee" not in str(err.value)


def test_none_and_booleans_in_form_fields_go_out_as_the_page_sends_them():
    router = settings_router()
    router.state["devices"][0]["type"] = None
    go(device, router, mac="02:00:00:00:00:aa", name="new", type=None)
    assert writes(router)[0][1]["type"] == ""


def test_backup_tightens_the_permissions_of_an_identical_file(tmp_path):
    router = settings_router()
    router.files["backupsettings.conf"] = b'<!--CalixVersion="0" crc32="1" type="backup" model="X" -->data'
    dest = tmp_path / "router.conf"
    go(backup, router, dest=str(dest))
    dest.chmod(0o644)
    result = go(backup, router, dest=str(dest))
    assert oct(dest.stat().st_mode & 0o777) == "0o600" and result["changed"] is True
