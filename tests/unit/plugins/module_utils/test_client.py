# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import hashlib
from urllib.error import URLError

import pytest

from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import (
    ExosAuthError,
    ExosClient,
    ExosError,
    normalize_mac,
)
from ansible_collections.workshop144.calix_exos.tests.unit.fakes import LOGIN_PAGE, FakeRouter

HOST = "192.0.2.1"


def logged_in(router, password="pw"):
    client = ExosClient(HOST, "admin", password, request=router)
    client.login()
    return client


def test_login_sends_sha256_of_user_nonce_password():
    router = FakeRouter(password="p@ss wörd")
    ExosClient(HOST, "admin", "p@ss wörd", request=router).login()
    params = [c[1] for c in router.calls if c[0] == "login.cgi"][0]
    expected = hashlib.sha256(("admin:%s:p@ss wörd" % params["nonce"]).encode("utf-8")).hexdigest()
    assert params["auth"] == expected
    assert params["Username"] == "admin"
    assert router.logged_in


def test_wrong_password_fails_once_with_counters_and_no_secret():
    router = FakeRouter(password="right")
    client = ExosClient(HOST, "admin", "wrong-secret", request=router)
    with pytest.raises(ExosAuthError) as err:
        client.login()
    assert router.endpoints().count("login.cgi") == 1
    assert err.value.access_status["locktime"] == 0
    assert "wrong-secret" not in str(err.value)
    auth = [c[1] for c in router.calls if c[0] == "login.cgi"][0]["auth"]
    assert auth not in str(err.value)


def test_error_body_raises_with_code():
    router = FakeRouter(replies={("x.cmd", "get"): "#ERROR_018"})
    client = logged_in(router)
    with pytest.raises(ExosError) as err:
        client.call("x.cmd", action="get")
    assert err.value.code == "018"
    assert err.value.endpoint == "x.cmd"
    assert err.value.action == "get"
    assert "#ERROR_018" in str(err.value)


def test_login_page_reply_raises_no_session():
    router = FakeRouter(replies={("x.cmd", "get"): LOGIN_PAGE})
    client = logged_in(router)
    with pytest.raises(ExosError) as err:
        client.call("x.cmd", action="get")
    assert "no session" in str(err.value)


def test_empty_body_is_none():
    router = FakeRouter(replies={("x.cmd", "readall"): ""})
    assert logged_in(router).call("x.cmd", action="readall") is None


def test_json_body_is_parsed():
    router = FakeRouter(replies={("x.cmd", "get"): '{ "a": "1" }'})
    assert logged_in(router).call("x.cmd", action="get") == {"a": "1"}


def test_garbage_body_raises_with_80_char_excerpt():
    router = FakeRouter(replies={("x.cmd", "get"): "<html>" + "z" * 500})
    client = logged_in(router)
    with pytest.raises(ExosError) as err:
        client.call("x.cmd", action="get")
    message = str(err.value)
    assert "x.cmd" in message and "get" in message
    assert "z" * 81 not in message
    assert "<html>" in message


def test_unreachable_raises_exoserror_naming_host():
    router = FakeRouter()
    for dummy in range(3):
        router.fail_next("login_nonce.cmd", None, URLError("timed out"))
    client = ExosClient(HOST, "admin", "pw", request=router)
    client.retry_delay = 0
    with pytest.raises(ExosError) as err:
        client.login()
    assert router.endpoints().count("login_nonce.cmd") == 3 and "login.cgi" not in router.endpoints()
    assert HOST in str(err.value)
    assert "login_nonce.cmd" in str(err.value)


def test_timeout_during_call_raises_exoserror():
    router = FakeRouter()
    client = logged_in(router)
    router.fail_next("x.cmd", "get", TimeoutError("timed out"))
    with pytest.raises(ExosError) as err:
        client.call("x.cmd", action="get")
    assert HOST in str(err.value)


def test_logout_swallows_connection_reset():
    router = FakeRouter()
    client = logged_in(router)
    router.fail_next("logout.cgi", None, ConnectionResetError())
    client.logout()


def test_context_manager_logs_in_and_out_when_body_raises():
    router = FakeRouter()
    with pytest.raises(RuntimeError):
        with ExosClient(HOST, "admin", "pw", request=router):
            assert router.logged_in
            raise RuntimeError("boom")
    assert "logout.cgi" in router.endpoints()
    assert not router.logged_in


def test_call_sends_params_as_form_fields():
    router = FakeRouter()
    logged_in(router).call("cgi_parameter_value.cmd", action="get", ejGetVal="a,b")
    assert router.calls[-1] == ("cgi_parameter_value.cmd", {"action": "get", "ejGetVal": "a,b"})


@pytest.mark.parametrize("raw", ["02-00-00-00-00-AA", "0200.0000.00AA", "02:00:00:00:00:AA", "0200000000aa", " 02:00:00:00:00:aa "])
def test_normalize_mac(raw):
    assert normalize_mac(raw) == "02:00:00:00:00:aa"


@pytest.mark.parametrize("raw", ["02:00", "", "02:00:00:00:00:zz", "02:00:00:00:00:aa:bb"])
def test_normalize_mac_rejects_bad(raw):
    with pytest.raises(ValueError):
        normalize_mac(raw)


def test_empty_password_fails_before_any_request():
    router = FakeRouter()
    with pytest.raises(ExosError) as err:
        ExosClient(HOST, "admin", "", request=router).login()
    assert router.calls == []
    assert "password" in str(err.value)


def test_broken_http_reply_is_exoserror():
    import http.client
    router = FakeRouter()
    client = logged_in(router)
    router.fail_next("x.cmd", "get", http.client.IncompleteRead(b""))
    with pytest.raises(ExosError) as err:
        client.call("x.cmd", action="get")
    assert HOST in str(err.value)


def test_logout_swallows_broken_http_reply():
    import http.client
    router = FakeRouter()
    client = logged_in(router)
    router.fail_next("logout.cgi", None, http.client.BadStatusLine(""))
    client.logout()


def test_refused_login_message_carries_http_status():
    router = FakeRouter(password="right")
    with pytest.raises(ExosAuthError) as err:
        ExosClient(HOST, "admin", "wrong", request=router).login()
    assert "HTTP 401" in str(err.value)


def test_login_answered_200_without_a_session_cookie_is_a_refusal():
    router = FakeRouter(password="right")
    router.refuse_silently = True
    with pytest.raises(ExosAuthError) as err:
        ExosClient(HOST, "admin", "wrong", request=router).login()
    assert router.endpoints().count("login.cgi") == 1
    assert "no session cookie" in str(err.value)
    assert "wrong" not in str(err.value)


def test_call_json_sends_a_json_body_and_parses_the_reply():
    router = FakeRouter()
    router.handlers["arp_spoof.cmd"] = lambda r, action, params: {"admin": "0", "echo": params}
    reply = logged_in(router).call_json("arp_spoof.cmd", {"action": "get"})
    assert reply == {"admin": "0", "echo": {"action": "get"}}
    assert router.json_calls == ["arp_spoof.cmd"]


def test_call_json_accepts_a_list_body():
    router = FakeRouter()
    router.handlers["advfw_load.cmd"] = lambda r, action, params: {params[0]: []}
    assert logged_in(router).call_json("advfw_load.cmd", ["dsv4"]) == {"dsv4": []}


def test_call_json_error_reply_raises():
    router = FakeRouter()
    router.handlers["arp_spoof.cmd"] = lambda r, action, params: "#ERROR_019"
    with pytest.raises(ExosError) as err:
        logged_in(router).call_json("arp_spoof.cmd", {"action": "set"})
    assert err.value.code == "019" and err.value.action == "set"


def test_call_text_returns_the_raw_reply():
    router = FakeRouter(replies={("portForwardingAssociations.cmd", "readall"): "TCP,192.0.2.5,80,80,0.0.0.0,8080,8080"})
    assert logged_in(router).call_text("portForwardingAssociations.cmd", action="readall").startswith("TCP,192.0.2.5")


def test_call_text_empty_reply_is_an_empty_string():
    assert logged_in(FakeRouter()).call_text("x.cmd", action="readall") == ""


def test_call_text_still_raises_on_error_and_login_page():
    router = FakeRouter(replies={("x.cmd", "a"): "#ERROR_060", ("x.cmd", "b"): LOGIN_PAGE})
    client = logged_in(router)
    with pytest.raises(ExosError):
        client.call_text("x.cmd", action="a")
    with pytest.raises(ExosError):
        client.call_text("x.cmd", action="b")


def test_error_message_carries_the_routers_own_wording():
    router = FakeRouter(replies={("x.cmd", "get"): "#ERROR_540"})
    with pytest.raises(ExosError) as err:
        logged_in(router).call("x.cmd", action="get")
    assert "Bridge mode can not use UPnP" in str(err.value)
    assert err.value.meaning == "Bridge mode can not use UPnP!"


def test_error_without_a_known_meaning_has_none():
    router = FakeRouter(replies={("x.cmd", "get"): "#ERROR_999"})
    with pytest.raises(ExosError) as err:
        logged_in(router).call("x.cmd", action="get")
    assert err.value.meaning is None and "#ERROR_999" in str(err.value)


def test_encrypt_secret_matches_the_admin_pages_algorithm():
    from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import encrypt_secret
    key = hashlib.sha256(b"example:abc123:psk2").digest()
    expected = "".join("%02x" % (key[i % 32] ^ ord(c)) for i, c in enumerate("correct horse battery staple, forty chars"))
    assert encrypt_secret("correct horse battery staple, forty chars", "example", "abc123", "psk2") == expected
    assert len(expected) == 2 * 41


def test_encrypt_secret_rejects_non_ascii():
    from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import encrypt_secret
    with pytest.raises(ValueError):
        encrypt_secret("pässword", "a", "b", "c")


def test_login_waits_out_a_router_that_is_briefly_not_answering():
    # Seen live: the web server stops answering for about 13 seconds after some changes.
    router = FakeRouter()
    router.fail_next("login_nonce.cmd", None, TimeoutError("timed out"))
    router.fail_next("login_nonce.cmd", None, TimeoutError("timed out"))
    client = ExosClient(HOST, "admin", "pw", request=router)
    client.retry_delay = 0
    client.login()
    assert router.logged_in and router.endpoints().count("login.cgi") == 1


def test_default_timeout_outlasts_the_routers_pause():
    from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import EXOS_ARGUMENT_SPEC
    assert EXOS_ARGUMENT_SPEC["timeout"]["default"] == 30
