# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import pytest

from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import ExosClient, ExosError
from ansible_collections.workshop144.calix_exos.plugins.modules import dhcp_reservation
from ansible_collections.workshop144.calix_exos.plugins.modules.dhcp_reservation import ReservationError, decide
from ansible_collections.workshop144.calix_exos.tests.unit.fakes import FakeRouter

AA = "02:00:00:00:00:aa"
BB = "02:00:00:00:00:bb"
LEASES = [{"dhcpPool": "lan", "ip": "192.0.2.150", "mac": AA}]
OLD = {"pool": "lan", "mac": AA, "ip": "192.0.2.150"}


def go(router, mac, ip=None, state="present", check_mode=False, pool="lan"):
    client = ExosClient("192.0.2.1", "admin", "pw", request=router)
    return dhcp_reservation.run({"mac": mac, "ip": ip, "pool": pool, "state": state}, client, check_mode)


def test_decide():
    assert decide([OLD], AA, "192.0.2.150", "lan", "present") == "none"
    assert decide([OLD], BB, "192.0.2.151", "lan", "present") == "add"
    assert decide([OLD], AA, "192.0.2.160", "lan", "present") == "replace"
    assert decide([OLD], AA, None, "lan", "absent") == "remove"
    assert decide([OLD], BB, None, "lan", "absent") == "none"
    with pytest.raises(ReservationError):
        decide([OLD], BB, "192.0.2.150", "lan", "present")


def test_present_same_is_no_change():
    router = FakeRouter(leases=LEASES)
    result = go(router, AA, "192.0.2.150")
    assert result["changed"] is False
    assert result["reservation"] == OLD
    assert router.writes() == []


def test_present_new_adds_and_reads_back():
    router = FakeRouter(leases=LEASES)
    result = go(router, BB, "192.0.2.151")
    assert result["changed"] is True
    assert router.writes() == [
        ("dhcpdstaticlease.cmd", {"action": "add", "dhcpPool": "lan", "mac": BB, "static_ip": "192.0.2.151"})
    ]
    assert result["reservation"] == {"pool": "lan", "mac": BB, "ip": "192.0.2.151"}
    assert router.endpoints()[-2:] == ["dhcp_reservation.cmd", "logout.cgi"]


def test_present_other_ip_replaces():
    router = FakeRouter(leases=LEASES)
    result = go(router, AA, "192.0.2.160")
    assert [w[1]["action"] for w in router.writes()] == ["remove", "add"]
    assert router.writes()[0][1]["rmLst"] == "192.0.2.150"
    assert result["changed"] is True
    assert result["reservation"]["ip"] == "192.0.2.160"
    assert router.leases == [{"dhcpPool": "lan", "ip": "192.0.2.160", "mac": AA}]


def test_present_ip_taken_fails_without_writing():
    router = FakeRouter(leases=LEASES)
    with pytest.raises(ReservationError) as err:
        go(router, BB, "192.0.2.150")
    assert AA in str(err.value)
    assert router.writes() == []
    assert router.endpoints()[-1] == "logout.cgi"


def test_absent_removes_by_mac():
    router = FakeRouter(leases=LEASES)
    result = go(router, AA.upper(), state="absent")
    assert router.writes() == [("dhcpdstaticlease.cmd", {"action": "remove", "rmLst": "192.0.2.150"})]
    assert result["changed"] is True
    assert result["reservation"] is None
    assert router.leases == []


def test_absent_missing_is_no_change():
    router = FakeRouter(leases=LEASES)
    result = go(router, BB, state="absent")
    assert result["changed"] is False
    assert router.writes() == []


@pytest.mark.parametrize("mac,ip,state", [(BB, "192.0.2.151", "present"), (AA, "192.0.2.160", "present"), (AA, None, "absent")])
def test_check_mode_sends_no_write(mac, ip, state):
    router = FakeRouter(leases=LEASES)
    result = go(router, mac, ip, state=state, check_mode=True)
    assert result["changed"] is True
    assert router.writes() == []
    assert router.leases == LEASES


def test_check_mode_reports_the_entry_that_would_exist():
    result = go(FakeRouter(leases=LEASES), BB, "192.0.2.151", check_mode=True)
    assert result["reservation"] == {"pool": "lan", "mac": BB, "ip": "192.0.2.151"}


@pytest.mark.parametrize("mac", ["02-00-00-00-00-AA", "0200.0000.00AA", "02:00:00:00:00:AA"])
def test_mac_formats_match(mac):
    router = FakeRouter(leases=LEASES)
    assert go(router, mac, "192.0.2.150")["changed"] is False


def test_router_storing_upper_case_mac_matches():
    router = FakeRouter(leases=[dict(LEASES[0], mac=AA.upper())])
    assert go(router, AA, "192.0.2.150")["changed"] is False


def test_bad_mac_fails_before_login():
    router = FakeRouter(leases=LEASES)
    with pytest.raises(ReservationError):
        go(router, "not-a-mac", "192.0.2.150")
    assert router.calls == []


def test_readback_mismatch_fails():
    router = FakeRouter(leases=LEASES)
    router.drop_writes = True
    with pytest.raises(ReservationError) as err:
        go(router, BB, "192.0.2.151")
    assert BB in str(err.value) and "192.0.2.151" in str(err.value)


def test_remove_readback_mismatch_fails():
    router = FakeRouter(leases=LEASES)
    router.drop_writes = True
    with pytest.raises(ReservationError):
        go(router, AA, state="absent")


def test_replace_restores_old_entry_when_add_fails():
    router = FakeRouter(leases=LEASES)
    router.fail_next("dhcpdstaticlease.cmd", "add", "#ERROR_018")
    with pytest.raises(ReservationError) as err:
        go(router, AA, "192.0.2.160")
    assert router.leases == LEASES
    assert "restored" in str(err.value)
    assert "192.0.2.150" in str(err.value)
    assert router.endpoints()[-1] == "logout.cgi"


def test_replace_reports_none_when_restore_also_fails():
    router = FakeRouter(leases=LEASES)
    router.fail_next("dhcpdstaticlease.cmd", "add", "#ERROR_018")
    router.fail_next("dhcpdstaticlease.cmd", "add", "#ERROR_018")
    with pytest.raises(ReservationError) as err:
        go(router, AA, "192.0.2.160")
    assert router.leases == []
    assert "no reservation" in str(err.value)
    assert AA in str(err.value)


def test_add_error_from_router_is_exoserror():
    router = FakeRouter(leases=LEASES)
    router.fail_next("dhcpdstaticlease.cmd", "add", "#ERROR_018")
    with pytest.raises(ExosError) as err:
        go(router, BB, "192.0.2.151")
    assert err.value.code == "018"


def test_diff_before_after():
    assert go(FakeRouter(leases=LEASES), AA, "192.0.2.160")["diff"] == {
        "before": OLD, "after": {"pool": "lan", "mac": AA, "ip": "192.0.2.160"}}
    assert go(FakeRouter(leases=LEASES), BB, "192.0.2.151")["diff"]["before"] is None
    assert go(FakeRouter(leases=LEASES), AA, state="absent")["diff"] == {"before": OLD, "after": None}
