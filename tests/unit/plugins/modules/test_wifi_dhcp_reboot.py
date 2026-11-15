# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import pytest

from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError
from ansible_collections.workshop144.calix_exos.plugins.modules import dhcp, reboot, wifi_network, wifi_radio, wifi_secondary_network
from ansible_collections.workshop144.calix_exos.tests.unit.fake_settings import client_for, settings_router, writes


def no_sleep(seconds):
    return None


def go(module, router, check_mode=False, **params):
    return module.run(params, client_for(router), check_mode, sleep=no_sleep)


# ---------------------------------------------------------------- dhcp

DHCP = dict(enabled=None, pool_start=None, pool_end=None, lease_seconds=None, dns_servers=None, lan_address=None,
            lan_netmask=None, hostname=None, domain=None, force=False)
PUBLIC = {"enabled": True, "pool_start": "192.0.2.100", "pool_end": "192.0.2.249", "lease_seconds": 43200, "dns_servers": [],
          "lan_address": "192.0.2.1", "lan_netmask": "255.255.255.0", "hostname": "router", "domain": "home.example"}


def dh(**changes):
    merged = dict(DHCP)
    merged.update(changes)
    return merged


def test_dhcp_no_change():
    router = settings_router()
    result = go(dhcp, router, **dh(lease_seconds=43200))
    assert result["changed"] is False and writes(router) == [] and result["dhcp"] == PUBLIC


def test_dhcp_lease_change_sends_every_field_the_page_sends():
    router = settings_router()
    result = go(dhcp, router, **dh(lease_seconds=3600))
    assert writes(router) == [("dhcpcfg.cmd", {
        "dnsHostName": "router", "dnsDomainName": "home.example", "enblDhcpSrv": "1", "dhcpServerIP": "192.0.2.1",
        "dhcpSubnetMask": "255.255.255.0", "dhcpEthStart": "192.0.2.100", "dhcpEthEnd": "192.0.2.249", "dnsType": "default",
        "dnsPrimary": "192.168.1.1", "dnsSecondary": "205.171.3.25", "dhcpLeasedTime": "3600", "dhcpAutoReserve": "0",
        "dhcpOptionTftpEn": "0", "dhcpOptionTftpOpt66": "", "dhcpOptionTftpOpt150": ""})]
    assert result["changed"] is True and result["dhcp"]["lease_seconds"] == 3600


def test_dhcp_custom_dns_and_back_to_default():
    router = settings_router()
    result = go(dhcp, router, **dh(dns_servers=["192.0.2.53"]))
    sent = writes(router)[0][1]
    assert sent["dnsType"] == "custom" and sent["dnsPrimary"] == "192.0.2.53" and sent["dnsSecondary"] == "0.0.0.0"
    assert result["dhcp"]["dns_servers"] == ["192.0.2.53"]
    assert go(dhcp, router, **dh(dns_servers=[]))["dhcp"]["dns_servers"] == []


def test_dhcp_off_sends_the_short_form():
    router = settings_router()
    go(dhcp, router, **dh(enabled=False))
    sent = writes(router)[0][1]
    assert sent["enblDhcpSrv"] == "0" and "dhcpEthStart" not in sent and "dhcpLeasedTime" not in sent


def test_dhcp_lan_address_needs_force_and_skips_the_read_back():
    router = settings_router()
    with pytest.raises(ExosModuleError) as err:
        go(dhcp, router, **dh(lan_address="192.0.2.2"))
    assert "force" in str(err.value) and writes(router) == []
    router = settings_router()
    router.drop_writes = True     # the router has moved: there is nothing to read back from
    result = go(dhcp, router, **dh(lan_address="192.0.2.2", force=True))
    assert writes(router)[0][1]["dhcpServerIP"] == "192.0.2.2"
    assert result["changed"] is True and result["dhcp"]["lan_address"] == "192.0.2.2"


@pytest.mark.parametrize("bad", [
    dict(lease_seconds=60), dict(pool_start="192.0.2.200", pool_end="192.0.2.150"), dict(pool_start="198.51.100.5"),
    dict(pool_start="192.0.2.1"), dict(dns_servers=["a", "b", "c"]), dict(dns_servers=["nope"]), dict(hostname="bad name"),
])
def test_dhcp_validation(bad):
    router = settings_router()
    with pytest.raises(ExosModuleError):
        go(dhcp, router, **dh(**bad))
    assert writes(router) == []


def test_dhcp_needs_an_option_check_mode_readback():
    with pytest.raises(ExosModuleError):
        go(dhcp, settings_router(), **DHCP)
    router = settings_router()
    assert go(dhcp, router, check_mode=True, **dh(lease_seconds=3600))["changed"] is True
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(dhcp, router, **dh(lease_seconds=3600))


# ---------------------------------------------------------------- wifi_secondary_network

NET = dict(ssid="guests", kind="guest", band="all", security="wpa2-wpa3", key="eight chars or more", isolation=None, state="present")


def net(**changes):
    merged = dict(NET)
    merged.update(changes)
    return merged


def test_secondary_network_created_with_an_encrypted_key_and_the_next_subnet():
    router = settings_router()
    result = go(wifi_secondary_network, router, **NET)
    endpoint, sent = [w for w in writes(router) if w[0] == "wireless_multiplessid.wl"][0]
    assert sent["actiondo"] == "1" and sent["oldname"] == "" and sent["networkType"] == "guest"
    assert sent["wlSsid"] == "guests" and sent["wlAuthMode"] == "wpa3-mixed" and sent["wlEnbl"] == "1"
    assert sent["wlSubnet"] == "1" and sent["smart_qos"] == "0"
    assert sent["wlGateway"] == "192.168.13.1" and sent["wlStartIp"] == "192.168.13.2" and sent["wlEndIp"] == "192.168.13.254"
    assert sent["nonce"] == "cd" * 32 and sent["wlWpaPsk"] != "eight chars or more" and len(sent["wlWpaPsk"]) == 2 * 19
    assert router.state["wifi"]["secondary"][0]["key"] == "eight chars or more"      # the router could decrypt it
    assert result["changed"] is True and "eight" not in repr(result)
    assert result["network"] == {"ssid": "guests", "kind": "guest", "band": "all", "security": "wpa2-wpa3", "isolation": True}


def test_secondary_network_same_including_the_key_is_no_change():
    router = settings_router()
    go(wifi_secondary_network, router, **NET)
    before = len(writes(router))
    assert go(wifi_secondary_network, router, **NET)["changed"] is False
    assert len(writes(router)) == before


def test_secondary_network_key_change_is_detected_and_sent_as_an_edit():
    router = settings_router()
    go(wifi_secondary_network, router, **NET)
    result = go(wifi_secondary_network, router, **net(key="another key entirely"))
    sent = [w[1] for w in writes(router) if w[0] == "wireless_multiplessid.wl"][-1]
    assert sent["actiondo"] == "2" and sent["oldname"] == "guests"
    assert result["changed"] is True and result["key_changed"] is True
    assert router.state["wifi"]["secondary"][0]["key"] == "another key entirely"


def test_secondary_network_without_a_key_keeps_the_one_it_has():
    router = settings_router()
    go(wifi_secondary_network, router, **NET)
    result = go(wifi_secondary_network, router, **net(key=None, security="wpa2"))
    assert result["changed"] is True and result["key_changed"] is False
    assert router.state["wifi"]["secondary"][0]["key"] == "eight chars or more"
    assert router.state["wifi"]["secondary"][0]["row"]["wlAuthMode"] == "psk2"


def test_secondary_network_removed():
    router = settings_router()
    go(wifi_secondary_network, router, **NET)
    result = go(wifi_secondary_network, router, **net(state="absent", key=None))
    sent = [w[1] for w in writes(router) if w[0] == "wireless_multiplessid.wl"][-1]
    assert sent["actiondo"] == "0" and sent["wlSsid"] == "guests" and "wlWpaPsk" not in sent
    assert result["network"] is None and router.state["wifi"]["secondary"] == []
    assert go(wifi_secondary_network, router, **net(state="absent", key=None))["changed"] is False


def test_secondary_network_custom_band_and_open_network():
    router = settings_router()
    go(wifi_secondary_network, router, **net(kind="custom", band="5", security="none", key=None, isolation=False))
    sent = [w[1] for w in writes(router) if w[0] == "wireless_multiplessid.wl"][0]
    assert sent["networkType"] == "custom_5" and sent["wlAuthMode"] == "disabled" and sent["wlWpaPsk"] == ""
    assert sent["wlSubnet"] == "0" and sent["wlGateway"] == "192.168.13.1"       # the 5 GHz pool's subnet


@pytest.mark.parametrize("bad", [
    dict(key="short"), dict(key=None), dict(ssid="x" * 33), dict(kind="custom", band="6", security="wpa2"),
    dict(kind="work_from_home", security="none", key=None), dict(key="pässword long"),
])
def test_secondary_network_validation(bad):
    router = settings_router()
    with pytest.raises(ExosModuleError):
        go(wifi_secondary_network, router, **net(**bad))
    assert writes(router) == []


def test_secondary_network_no_free_slot_check_mode_readback():
    router = settings_router()
    router.state["wifi"]["pool"]["ALL"] = 0
    with pytest.raises(ExosModuleError):
        go(wifi_secondary_network, router, **NET)
    router = settings_router()
    assert go(wifi_secondary_network, router, check_mode=True, **NET)["changed"] is True
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(wifi_secondary_network, router, **NET)


# ---------------------------------------------------------------- wifi_network

def test_primary_network_no_change_even_with_the_same_key_given():
    router = settings_router()
    result = go(wifi_network, router, ssid="example", security="wpa-wpa2", key="correct horse battery", hidden=False)
    assert result["changed"] is False and writes(router) == []
    assert result["network"] == {"ssid": "example", "security": "wpa-wpa2", "hidden": False} and "horse" not in repr(result)


def test_primary_network_hidden_change_resends_the_current_key():
    router = settings_router()
    result = go(wifi_network, router, ssid=None, security=None, key=None, hidden=True)
    endpoint, sent = [w for w in writes(router) if w[0] == "wireless_multiplessid.wl"][0]
    assert sent["wlSsidIdx"] == "1" and sent["wlHidden"] == "1" and sent["wlSsidSuffix"] == "0"
    assert sent["wlSsid"] == "example" and sent["wlAuthMode"] == "psk+psk2" and "actiondo" not in sent
    assert router.state["wifi"]["primary"] == {"ssid": "example", "auth": "psk+psk2", "hidden": 1, "key": "correct horse battery"}
    assert result["changed"] is True and result["key_changed"] is False


def test_primary_network_name_security_and_key_change():
    router = settings_router()
    result = go(wifi_network, router, ssid="new name", security="wpa2-wpa3", key="a brand new key", hidden=None)
    assert router.state["wifi"]["primary"] == {"ssid": "new name", "auth": "wpa3-mixed", "hidden": 0, "key": "a brand new key"}
    assert result["key_changed"] is True and "brand" not in repr(result)


def test_primary_network_validation_check_mode_readback():
    with pytest.raises(ExosModuleError):
        go(wifi_network, settings_router(), ssid=None, security=None, key=None, hidden=None)
    with pytest.raises(ExosModuleError):
        go(wifi_network, settings_router(), ssid=None, security=None, key="short", hidden=None)
    router = settings_router()
    assert go(wifi_network, router, check_mode=True, ssid=None, security=None, key=None, hidden=True)["changed"] is True
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(wifi_network, router, ssid=None, security=None, key=None, hidden=True)


# ---------------------------------------------------------------- wifi_radio

RADIO = dict(band="6", enabled=None, dfs=None, mu_mimo=None, wifi6=None, wifi7=None, wide_channels=None, psc_only=None)


def radio(**changes):
    merged = dict(RADIO)
    merged.update(changes)
    return merged


def test_radio_change_sends_every_radio_in_page_order_with_string_flags():
    router = settings_router()
    result = go(wifi_radio, router, **radio(mu_mimo=True))
    endpoint, sent = writes(router)[0]
    assert endpoint == "wireless_radiosetup.wl" and endpoint in router.json_calls
    assert [r["band"] for r in sent] == ["2.4G", "5G", "6G"]
    assert sent[2] == {"enable": "1", "band": "6G", "dfs": "0", "mimo": "1", "psc_only": "1", "802.11ax": "1", "160_80+80": "1"}
    assert sent[0] == {"enable": "1", "band": "2.4G", "dfs": "0", "mimo": "0", "psc_only": "0", "802.11ax": "1"}
    assert result["changed"] is True and result["radio"]["mu_mimo"] is True and result["radio"]["band"] == "6"


def test_radio_no_change_unsupported_option_and_unknown_band():
    router = settings_router()
    assert go(wifi_radio, router, **radio(enabled=True, psc_only=True))["changed"] is False and writes(router) == []
    with pytest.raises(ExosModuleError):          # the 2.4 GHz radio has no wide-channel setting
        go(wifi_radio, settings_router(), **radio(band="2.4", wide_channels=True))
    router = settings_router()
    router.state["wifi"]["radios"].pop()
    with pytest.raises(ExosModuleError):
        go(wifi_radio, router, **radio(mu_mimo=True))


def test_radio_two_band_router_gets_the_pages_third_placeholder():
    router = settings_router()
    router.state["wifi"]["radios"].pop()
    go(wifi_radio, router, **radio(band="5", mu_mimo=True))
    sent = writes(router)[0][1]
    assert len(sent) == 3 and sent[2] == {"enable": "0", "dfs": "0", "mimo": "0", "psc_only": "0"}


def test_radio_needs_an_option_check_mode_readback():
    with pytest.raises(ExosModuleError):
        go(wifi_radio, settings_router(), **RADIO)
    router = settings_router()
    assert go(wifi_radio, router, check_mode=True, **radio(enabled=False))["changed"] is True
    assert writes(router) == []
    router = settings_router()
    router.drop_writes = True
    with pytest.raises(ExosModuleError):
        go(wifi_radio, router, **radio(enabled=False))


# ---------------------------------------------------------------- reboot

def test_reboot_sends_the_request_and_waits_for_the_router_to_answer():
    router = settings_router()
    naps = []
    result = reboot.run({"wait": True, "timeout": 600, "settle": 80}, client_for(router), False, sleep=naps.append)
    assert router.state["rebooted"] is True
    assert naps[0] == 80 and len(naps) >= 3          # the fixed settle time, then polls while it was down
    assert result["changed"] is True and result["rebooted"] is True and result["waited_seconds"] >= 80
    assert "logout.cgi" not in router.endpoints()    # the session died with the reboot


def test_reboot_without_waiting_and_check_mode():
    router = settings_router()
    naps = []
    result = reboot.run({"wait": False, "timeout": 600, "settle": 80}, client_for(router), False, sleep=naps.append)
    assert router.state["rebooted"] is True and naps == [] and result["waited_seconds"] == 0
    router = settings_router()
    result = reboot.run({"wait": True, "timeout": 600, "settle": 80}, client_for(router), True, sleep=naps.append)
    assert "rebooted" not in router.state and result["changed"] is True and result["rebooted"] is False


def test_reboot_times_out_when_the_router_stays_down():
    router = settings_router(boot_polls=10000)
    with pytest.raises(ExosModuleError) as err:
        reboot.run({"wait": True, "timeout": 120, "settle": 80}, client_for(router), False, sleep=no_sleep)
    assert "did not answer" in str(err.value)
