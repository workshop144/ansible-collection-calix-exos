# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Session handling for the local web interface of a Calix EXOS router.

Unofficial. See docs/api-notes.md in the collection for what is known about the interface.
"""

from __future__ import annotations

import hashlib
import json
import re
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.parse import urlencode

from ansible.module_utils.basic import env_fallback
from ansible.module_utils.urls import Request

LOGIN_PAGE_MARKER = "Login - Residential Gateway"
ERROR_PREFIX = "#ERROR_"
EXCERPT_LENGTH = 80

EXOS_ARGUMENT_SPEC = dict(
    host=dict(type="str", required=True),
    username=dict(type="str", default="admin"),
    password=dict(type="str", required=True, no_log=True, fallback=(env_fallback, ["CALIX_EXOS_PASSWORD"])),
    validate_certs=dict(type="bool", default=False),
    timeout=dict(type="int", default=15),
)


class ExosError(Exception):
    """A request to the router failed. ``code`` is the nnn of an ``#ERROR_nnn`` reply, if any."""

    def __init__(self, message, endpoint=None, action=None, code=None):
        super().__init__(message)
        self.endpoint = endpoint
        self.action = action
        self.code = code


class ExosAuthError(ExosError):
    """The router refused the login. ``access_status`` holds its lockout counters."""

    def __init__(self, message, access_status=None):
        super().__init__(message, endpoint="login.cgi")
        self.access_status = access_status or {}


def normalize_mac(value):
    """Return a MAC address as lower-case, colon-separated pairs."""
    digits = re.sub(r"[\s:.\-]", "", str(value)).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", digits):
        raise ValueError("not a MAC address: %r" % (value,))
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


class ExosClient:
    """One session with one router. Use as a context manager: it logs in and always logs out."""

    def __init__(self, host, username, password, validate_certs=False, timeout=15, request=None):
        self.host = host
        self.username = username
        self._password = password
        self.base_url = "https://%s" % host
        self._request = request or Request(validate_certs=validate_certs, timeout=timeout, cookies=CookieJar())
        self._headers = {
            "Content-Type": "application/x-www-form-urlencoded;charset=utf-8;",
            "Origin": self.base_url,
            "Referer": self.base_url + "/",
        }

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.logout()
        return False

    def _post(self, endpoint, params=None):
        """POST form fields and return the reply body as text. HTTPError is left to the caller."""
        action = (params or {}).get("action")
        try:
            response = self._request.post(
                "%s/%s" % (self.base_url, endpoint), data=urlencode(params or {}), headers=self._headers
            )
            return response.read().decode("utf-8", "replace")
        except HTTPError:
            raise
        except (OSError, ValueError) as err:
            reason = getattr(err, "reason", None) or err
            raise ExosError(
                "cannot reach %s (%s): %s" % (self.host, endpoint, reason), endpoint=endpoint, action=action
            ) from None

    def login(self):
        """Log in once. A refusal is never retried: the router locks the account after repeats."""
        try:
            nonce = self._post("login_nonce.cmd").strip()
        except HTTPError as err:
            raise ExosError(
                "HTTP %s from %s (login_nonce.cmd)" % (err.code, self.host), endpoint="login_nonce.cmd"
            ) from None
        if not re.fullmatch(r"[0-9a-fA-F]{16,128}", nonce):
            raise ExosError(
                "%s did not return a login nonce; is this a Calix EXOS router?" % self.host,
                endpoint="login_nonce.cmd",
            )
        auth = hashlib.sha256(("%s:%s:%s" % (self.username, nonce, self._password)).encode("utf-8")).hexdigest()
        try:
            self._post("login.cgi", {"Username": self.username, "auth": auth, "nonce": nonce})
        except HTTPError:
            status = self._access_status()
            raise ExosAuthError(
                "login to %s as %s was refused (not retried); router access status: %s"
                % (self.host, self.username, json.dumps(status, sort_keys=True)),
                access_status=status,
            ) from None

    def _access_status(self):
        try:
            return json.loads(self._post("get_access_status.cmd", {"Username": self.username}))
        except (HTTPError, ExosError, ValueError):
            return {}

    def logout(self):
        """End the session. The router resets the connection afterwards, so nothing here raises."""
        try:
            self._post("logout.cgi")
        except (HTTPError, ExosError):
            pass

    def call(self, endpoint, **params):
        """POST to an endpoint and return its parsed JSON reply, or None for an empty reply."""
        action = params.get("action")
        where = "%s%s" % (endpoint, " action=%s" % action if action else "")
        try:
            body = self._post(endpoint, params).strip()
        except HTTPError as err:
            raise ExosError(
                "HTTP %s from %s for %s" % (err.code, self.host, where), endpoint=endpoint, action=action
            ) from None
        if not body:
            return None
        if body.startswith(ERROR_PREFIX):
            code = body[len(ERROR_PREFIX):].split()[0] if body[len(ERROR_PREFIX):].split() else ""
            raise ExosError(
                "%s returned %s%s for %s" % (self.host, ERROR_PREFIX, code, where),
                endpoint=endpoint, action=action, code=code,
            )
        if LOGIN_PAGE_MARKER in body:
            raise ExosError(
                "no session on %s: it answered %s with its login page" % (self.host, where),
                endpoint=endpoint, action=action,
            )
        try:
            return json.loads(body)
        except ValueError:
            raise ExosError(
                "unexpected reply from %s for %s: %r" % (self.host, where, body[:EXCERPT_LENGTH]),
                endpoint=endpoint, action=action,
            ) from None


def client_from_module(module):
    """Build a client from a module's shared connection options."""
    params = module.params
    return ExosClient(
        params["host"], params["username"], params["password"],
        validate_certs=params["validate_certs"], timeout=params["timeout"],
    )
