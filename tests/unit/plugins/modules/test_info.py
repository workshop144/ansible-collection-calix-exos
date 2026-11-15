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


def make(router):
    return ExosClient("192.0.2.1", "admin", "pw", request=router)


def test_subset_only_calls_its_endpoints():
    router = FakeRouter(replies=replies.canned())
    result = info.run({"gather_subset": ["system"]}, make(router))
    assert list(result["exos"]) == ["system"]
    assert "status_system.cmd" in router.endpoints()
    assert "wlinfo.cmd" not in router.endpoints()
    assert "device_table.cmd" not in router.endpoints()


def test_all_returns_every_subset():
    router = FakeRouter(replies=replies.canned(), leases=replies.RESERVATIONS["staticIpLease"])
    result = info.run({"gather_subset": ["all"]}, make(router))
    assert set(result["exos"]) == set(SUBSETS)
    assert result["exos"]["system"]["model"] == "GS4227W"
    assert result["exos"]["security"]["upnp"] is False
    assert len(result["exos"]["dhcp_reservations"]) == 3


def test_never_changed():
    router = FakeRouter(replies=replies.canned())
    assert info.run({"gather_subset": ["all"]}, make(router))["changed"] is False


def test_no_secret_in_result():
    router = FakeRouter(replies=replies.canned())
    result = info.run({"gather_subset": ["all"]}, make(router))
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
        info.run({"gather_subset": ["all"]}, make(router))
    assert router.endpoints()[-1] == "logout.cgi"
