# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations


class ModuleDocFragment:
    DOCUMENTATION = r"""
options:
  host:
    description:
      - Name or address of the router. The module talks HTTPS to it on port 443.
    type: str
    required: true
  username:
    description:
      - Account to log in as.
    type: str
    default: admin
  password:
    description:
      - Password of that account. It is never logged or returned.
      - If not set, the value of the E(CALIX_EXOS_PASSWORD) environment variable is used.
    type: str
    required: true
  validate_certs:
    description:
      - Whether to verify the router's TLS certificate.
      - The default is V(false) because these routers ship with a self-signed certificate.
    type: bool
    default: false
  timeout:
    description:
      - Seconds to wait for each request.
      - The router's web server can stop answering for around 15 seconds while it applies some
        changes, so a much shorter value makes tasks fail now and then.
    type: int
    default: 30
notes:
  - Unofficial. Not affiliated with or endorsed by Calix. Tested on the GS4227 and GS4227W with
    EXOS 25.4.0; a firmware update may break it.
  - The module runs on the control node, so use C(connection=local) or C(delegate_to=localhost).
  - Each run logs in, does its work and logs out. A refused login is never retried, because the
    router locks the account after repeated failures.
"""
