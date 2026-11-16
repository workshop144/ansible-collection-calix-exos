# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Session handling for the local web interface of a Calix EXOS router.

Unofficial. See docs/api-notes.md in the collection for what is known about the interface.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.parse import urlencode

from ansible.module_utils.basic import env_fallback
from ansible.module_utils.urls import Request

from ansible_collections.workshop144.calix_exos.plugins.module_utils.errors import meaning as error_meaning

LOGIN_PAGE_MARKER = "Login - Residential Gateway"
ERROR_PREFIX = "#ERROR_"
EXCERPT_LENGTH = 80
KEY_BEARING = ("wlinfo.cmd", "ddnsmngr.cmd", "wireless_multiplessid.wl")   # replies never quoted in an error
SESSION_COOKIE = "Authorization"

EXOS_ARGUMENT_SPEC = dict(
    host=dict(type="str", required=True),
    username=dict(type="str", default="admin"),
    password=dict(type="str", required=True, no_log=True, fallback=(env_fallback, ["CALIX_EXOS_PASSWORD"])),
    validate_certs=dict(type="bool", default=False),
    timeout=dict(type="int", default=15),
)


def _form_value(value):
    """A form field as the admin page's own serializer writes it."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


class ExosError(Exception):
    """A request to the router failed. ``code`` is the nnn of an ``#ERROR_nnn`` reply, if any."""

    def __init__(self, message, endpoint=None, action=None, code=None):
        super().__init__(message)
        self.endpoint = endpoint
        self.action = action
        self.code = code
        self.meaning = error_meaning(code) if code else None
        self.unreachable = False   # True when the router could not be reached at all


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
        # No proxy (the router is on the local network) and no redirects (a redirect is never a
        # normal reply here, and following one would hide a refused login).
        self._request = request or Request(
            validate_certs=validate_certs, timeout=timeout, cookies=CookieJar(),
            use_proxy=False, follow_redirects="none",
        )
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

    def _post(self, endpoint, params=None, as_json=False):
        """POST form fields (or a JSON body) and return the reply body as text.

        Most of the router's endpoints take form fields; some take a JSON body. HTTPError is left
        to the caller.
        """
        action = params.get("action") if isinstance(params, dict) else None
        headers = self._headers
        if as_json:
            headers = dict(headers, **{"Content-Type": "application/json"})
            body = json.dumps(params)
        else:
            body = urlencode({key: _form_value(value) for key, value in (params or {}).items()})
        try:
            response = self._request.post("%s/%s" % (self.base_url, endpoint), data=body, headers=headers)
            return response.read().decode("utf-8", "replace")
        except HTTPError:
            raise
        except (OSError, ValueError, http.client.HTTPException) as err:
            reason = getattr(err, "reason", None) or err or type(err).__name__
            failure = ExosError("cannot reach %s (%s): %s" % (self.host, endpoint, reason), endpoint=endpoint, action=action)
            failure.unreachable = True
            raise failure from None

    def login(self):
        """Log in once. A refusal is never retried: the router locks the account after repeats."""
        if not self._password:
            raise ExosError(
                "no password given for %s (set the password option or CALIX_EXOS_PASSWORD)" % self.host,
                endpoint="login.cgi",
            )
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
        except HTTPError as err:
            status = self._access_status()
            raise ExosAuthError(
                "login to %s as %s was refused (HTTP %s, not retried); router access status: %s"
                % (self.host, self.username, err.code, json.dumps(status, sort_keys=True)),
                access_status=status,
            ) from None
        # A login the router did not accept can still be answered with HTTP 200. The session
        # cookie is what shows it worked.
        cookies = getattr(self._request, "cookies", None)
        if cookies is not None and not any(getattr(c, "name", None) == SESSION_COOKIE for c in cookies):
            status = self._access_status()
            raise ExosAuthError(
                "login to %s as %s was not accepted (no session cookie was set, not retried); "
                "router access status: %s" % (self.host, self.username, json.dumps(status, sort_keys=True)),
                access_status=status,
            )

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

    def _exchange(self, endpoint, params, as_json=False):
        """POST and return the reply text, raising for an HTTP error, ``#ERROR_nnn`` or the login page."""
        action = params.get("action") if isinstance(params, dict) else None
        where = "%s%s" % (endpoint, " action=%s" % action if action else "")
        try:
            body = self._post(endpoint, params, as_json=as_json).strip()
        except HTTPError as err:
            raise ExosError(
                "HTTP %s from %s for %s" % (err.code, self.host, where), endpoint=endpoint, action=action
            ) from None
        if body.startswith(ERROR_PREFIX):
            parts = body[len(ERROR_PREFIX):].split()
            code = parts[0] if parts else ""
            said = error_meaning(code)
            raise ExosError(
                "%s returned %s%s%s for %s" % (self.host, ERROR_PREFIX, code, " (%s)" % said if said else "", where),
                endpoint=endpoint, action=action, code=code,
            )
        if LOGIN_PAGE_MARKER in body or body.lower().startswith("<!doctype html"):
            raise ExosError(
                "no session on %s: it answered %s with its login page" % (self.host, where),
                endpoint=endpoint, action=action,
            )
        return body, where, action

    @staticmethod
    def _parse(body, host, where, endpoint, action):
        if not body:
            return None
        try:
            return json.loads(body)
        except ValueError:
            shown = "(not shown: it can hold keys)" if endpoint in KEY_BEARING else repr(body[:EXCERPT_LENGTH])
            raise ExosError(
                "unexpected reply from %s for %s: %s" % (host, where, shown), endpoint=endpoint, action=action
            ) from None

    def call(self, endpoint, **params):
        """POST form fields and return the parsed JSON reply, or None for an empty reply."""
        body, where, action = self._exchange(endpoint, params)
        return self._parse(body, self.host, where, endpoint, action)

    def call_text(self, endpoint, **params):
        """POST form fields and return the reply as text. Some endpoints answer in plain text."""
        return self._exchange(endpoint, params)[0]

    def call_json(self, endpoint, payload):
        """POST a JSON body and return the parsed JSON reply, or None for an empty reply."""
        body, where, action = self._exchange(endpoint, payload, as_json=True)
        return self._parse(body, self.host, where, endpoint, action)

    def download(self, path):
        """GET a file from the router and return its bytes."""
        try:
            data = self._request.get("%s/%s" % (self.base_url, path), headers={"Referer": self.base_url + "/"}).read()
        except HTTPError as err:
            raise ExosError("HTTP %s from %s for %s" % (err.code, self.host, path), endpoint=path) from None
        except (OSError, ValueError, http.client.HTTPException) as err:
            reason = getattr(err, "reason", None) or err or type(err).__name__
            raise ExosError("cannot reach %s (%s): %s" % (self.host, path, reason), endpoint=path) from None
        head = data[:400].decode("utf-8", "replace")
        if LOGIN_PAGE_MARKER in head or head.lstrip().lower().startswith("<!doctype html"):
            raise ExosError("no session on %s: it answered %s with its login page" % (self.host, path), endpoint=path)
        return data

    def nonce(self):
        """A fresh nonce for a write that carries an encrypted secret."""
        value = self.call_text("get_nonce.cmd").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{16,128}", value):
            raise ExosError("%s did not return a nonce" % self.host, endpoint="get_nonce.cmd")
        return value


def encrypt_secret(secret, first, nonce, second):
    """Encrypt a secret the way the router's admin page does before sending it.

    The key is ``sha256("<first>:<nonce>:<second>")``; each character of the secret is XORed with
    the key bytes in turn and written as two hex digits. What ``first`` and ``second`` are depends
    on the setting (for a Wi-Fi key: the network name and its security mode).
    """
    key = hashlib.sha256(("%s:%s:%s" % (first, nonce, second)).encode("utf-8")).digest()
    try:
        data = str(secret).encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("the secret must be printable ASCII") from None
    return "".join("%02x" % (key[i % len(key)] ^ byte) for i, byte in enumerate(data))


def decrypt_secret(cipher_hex, first, nonce, second):
    """Undo :func:`encrypt_secret`. The router returns stored keys encrypted this way."""
    key = hashlib.sha256(("%s:%s:%s" % (first, nonce, second)).encode("utf-8")).digest()
    try:
        data = bytes.fromhex(str(cipher_hex))
    except ValueError:
        raise ValueError("not an encrypted secret from the router") from None
    return "".join(chr(key[i % len(key)] ^ byte) for i, byte in enumerate(data))


def client_from_module(module):
    """Build a client from a module's shared connection options."""
    params = module.params
    return ExosClient(
        params["host"], params["username"], params["password"],
        validate_certs=params["validate_certs"], timeout=params["timeout"],
    )
