#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
module: backup
short_description: Download the configuration backup of a Calix EXOS router
version_added: "0.2.0"
description:
  - Saves the router's configuration backup (Utilities > Backup & Restore in its admin page) to
    a file on the control node.
  - The backup is one line of readable header followed by data only the router can read. It
    holds the router's settings, so the file is written readable by its owner only.
  - This collection does not restore a backup; do that in the router's admin page.
author:
  - Workshop 144 (@workshop144)
options:
  dest:
    description:
      - Path of the file to write on the control node.
    type: path
    required: true
extends_documentation_fragment:
  - workshop144.calix_exos.connection
attributes:
  check_mode:
    support: full
    description: Downloads the backup to compare it but writes no file.
  diff_mode:
    support: none
    description: The backup is not readable, so no diff is shown.
"""

EXAMPLES = r"""
- name: Keep a copy of the router's configuration
  workshop144.calix_exos.backup:
    host: 192.0.2.1
    password: "{{ router_password }}"
    dest: "backups/router-{{ ansible_date_time.date | default('today') }}.conf"
"""

RETURN = r"""
backup:
  description: Where the backup was written, its size, and what its header says.
  returned: always
  type: dict
  sample: {"dest": "backups/router.conf", "size": 198458, "model": "GS4227W", "config_version": "25.4.0.0.57",
           "crc32": "0badf00d"}
"""

import os
import re
import tempfile

from ansible_collections.workshop144.calix_exos.plugins.module_utils.base import ExosModuleError, run_module


def _header(data):
    head = data[:600].decode("utf-8", "replace")
    if not head.startswith("<!--Calix") or 'type="backup"' not in head.split("-->")[0]:
        raise ExosModuleError("what the router returned is not a configuration backup")
    line = head.split("-->")[0]

    def field(name):
        match = re.search(r'%s="([^"]*)"' % name, line)
        return match.group(1) if match else None

    return {"model": field("model"), "config_version": field("ConfigVersion"), "crc32": field("crc32")}


def run(params, client, check_mode):
    dest = os.path.abspath(str(params["dest"]))   # type=path has already expanded ~ and variables
    with client:
        data = client.download("backupsettings.conf")
    header = _header(data)
    try:
        with open(dest, "rb") as existing:
            same = existing.read() == data
    except OSError:
        same = False
    if not same and not check_mode:
        folder = os.path.dirname(dest)
        if not os.path.isdir(folder):
            raise ExosModuleError("the directory %s does not exist" % folder)
        handle, temp = tempfile.mkstemp(dir=folder, prefix=".exos-backup-")
        try:
            with os.fdopen(handle, "wb") as out:
                out.write(data)
            os.chmod(temp, 0o600)
            os.replace(temp, dest)
        except OSError as err:
            if os.path.exists(temp):
                os.unlink(temp)
            raise ExosModuleError("could not write %s: %s" % (dest, err)) from None
    loose = same and bool(os.stat(dest).st_mode & 0o077)
    if loose and not check_mode:
        os.chmod(dest, 0o600)
    result = {"dest": str(params["dest"]), "size": len(data)}
    result.update(header)
    return {"changed": not same or loose, "backup": result}


def main():
    run_module(dict(dest=dict(type="path", required=True)), run)


if __name__ == "__main__":
    main()
