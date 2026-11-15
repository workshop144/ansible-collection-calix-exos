# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""A stand-in for the router, used as the client's transport in unit tests."""

from __future__ import annotations

import hashlib
import json
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlparse

LOGIN_PAGE = "<!DOCTYPE html><html><head><title>Login - Residential Gateway</title></head></html>"
ACCESS_STATUS = {"user_type": 0, "status": 1, "count": 0, "total_count": 0, "locktime": 0}
WRITE_ACTIONS = ("add", "remove")


class FakeResponse:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body if isinstance(self._body, bytes) else self._body.encode("utf-8")


class FakeCookie:
    def __init__(self, name):
        self.name = name


class FakeRouter:
    """Implements login, logout, the reservation table and canned replies.

    Every request is recorded in ``calls`` as ``(endpoint, params)``.
    """

    def __init__(self, password="pw", username="admin", leases=None, replies=None):
        self.password = password
        self.username = username
        self.leases = [dict(x) for x in (leases or [])]
        self.replies = dict(replies or {})
        self.calls = []
        self.json_calls = []   # endpoints that were sent a JSON body
        self.handlers = {}     # endpoint -> callable(router, action, params) returning str, dict or list
        self.state = {}        # free-form state for handlers
        self.files = {}        # path -> bytes, for downloads
        self.logged_in = False
        self.drop_writes = False
        self.refuse_silently = False  # answer a wrong password with HTTP 200 and no cookie
        self.cookies = []
        self._nonce_count = 0
        self._nonce = None
        self._failures = {}

    def fail_next(self, endpoint, action, failure):
        """Make the next matching request return ``failure`` (a body) or raise it (an exception).

        Calls queue up: ``None`` lets one matching request through untouched.
        """
        self._failures.setdefault((endpoint, action), []).append(failure)

    def writes(self):
        return [c for c in self.calls if c[0] == "dhcpdstaticlease.cmd" and c[1].get("action") in WRITE_ACTIONS]

    def endpoints(self):
        return [c[0] for c in self.calls]

    def get(self, url, headers=None):
        """A plain download. ``files`` maps a path to its bytes; anything else is the login page."""
        path = urlparse(url).path.lstrip("/")
        self.calls.append(("GET " + path, {}))
        if not self.logged_in or path not in self.files:
            return FakeResponse(LOGIN_PAGE)
        return FakeResponse(self.files[path])

    def post(self, url, data=None, headers=None):
        endpoint = urlparse(url).path.lstrip("/")
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        if "json" in (headers or {}).get("Content-Type", ""):
            params = json.loads(data or "null")
            self.json_calls.append(endpoint)
        else:
            params = dict(parse_qsl(data or "", keep_blank_values=True))
        self.calls.append((endpoint, params))
        action = params.get("action") if isinstance(params, dict) else None

        queued = self._failures.get((endpoint, action))
        if queued:
            failure = queued.pop(0)
            if isinstance(failure, BaseException):
                raise failure
            if failure is not None:
                return FakeResponse(failure)

        return FakeResponse(self._dispatch(url, endpoint, action, params))

    def _dispatch(self, url, endpoint, action, params):
        if endpoint == "login_nonce.cmd":
            self._nonce_count += 1
            self._nonce = hashlib.sha256(str(self._nonce_count).encode()).hexdigest()
            return self._nonce
        if endpoint == "login.cgi":
            expected = hashlib.sha256(
                ("%s:%s:%s" % (self.username, self._nonce, self.password)).encode("utf-8")
            ).hexdigest()
            if params.get("Username") == self.username and params.get("auth") == expected and params.get("nonce") == self._nonce:
                self.logged_in = True
                self.cookies.append(FakeCookie("Authorization"))
                return ""
            if self.refuse_silently:
                return ""
            raise HTTPError(url, 401, "Unauthorized", {}, None)
        if endpoint == "get_access_status.cmd":
            return json.dumps(ACCESS_STATUS)
        if endpoint == "logout.cgi":
            self.logged_in = False
            del self.cookies[:]
            return ""
        if not self.logged_in:
            return LOGIN_PAGE
        if endpoint in self.handlers:
            reply = self.handlers[endpoint](self, action, params)
            return reply if isinstance(reply, str) else json.dumps(reply)
        if endpoint == "dhcp_reservation.cmd" and action == "init":
            return json.dumps({
                "networks": [{"network": "Primary", "dhcpPool": "lan", "dhcpEnbled": "1",
                              "dhcpStart": "192.0.2.100", "dhcpEnd": "192.0.2.249"}],
                "staticIpLease": self.leases,
            })
        if endpoint == "dhcpdstaticlease.cmd" and action == "add":
            if not self.drop_writes:
                self.leases.append({"dhcpPool": params["dhcpPool"], "ip": params["static_ip"], "mac": params["mac"]})
            return ""
        if endpoint == "dhcpdstaticlease.cmd" and action == "remove":
            if not self.drop_writes:
                self.leases = [x for x in self.leases if x["ip"] != params["rmLst"]]
            return ""
        return self.replies.get((endpoint, action), "")
