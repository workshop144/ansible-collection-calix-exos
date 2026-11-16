# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""The part every module shares: options, the session, and turning failures into task failures."""

from __future__ import annotations

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.workshop144.calix_exos.plugins.module_utils.client import (
    EXOS_ARGUMENT_SPEC,
    ExosError,
    client_from_module,
)


class ExosModuleError(Exception):
    """The request cannot be met, or the router did not end up as asked."""


def flag(value):
    """True for the ways the router spells on: 1, "1", "yes", "true", "on", "enabled"."""
    return str(value).strip().lower() in ("1", "true", "on", "yes", "enabled")


ON = ("1", "true", "on", "yes", "enabled")
OFF = ("0", "false", "off", "no", "disabled")


def on_off(value, what):
    """A flag from the router as a bool. Anything that is not a known spelling of on or off is an
    error: a setting the collection cannot read must never be taken for off."""
    text = str(value).strip().lower()
    if text in ON:
        return True
    if text in OFF:
        return False
    raise ExosError("the router reports %s as %r, which this collection does not understand" % (what, value))


BUSY = "018"   # "Internal Error.": what the router answers when a change arrives while it is applying the last one


def add_when_ready(add, is_there, sleep, tries=3, delay=3):
    """Send an add, trying again if the router answers that it is busy.

    Before each further try, ``is_there()`` is asked whether the entry exists after all, so that
    an add that worked but was answered with an error is never sent twice.
    """
    for attempt in range(tries):
        try:
            add()
            return
        except ExosError as err:
            if err.code != BUSY or attempt == tries - 1:
                raise
        sleep(delay)
        if is_there():
            return


def changed_result(before, after, **extra):
    """The usual result of a settings module: changed when before and after differ, with a diff."""
    result = {"changed": before != after, "diff": {"before": before, "after": after}}
    result.update(extra)
    return result


def run_module(argument_spec, run, **module_kwargs):
    """Build the module and call ``run(params, client, check_mode)``, which returns the result."""
    spec = dict(EXOS_ARGUMENT_SPEC)
    spec.update(argument_spec)
    module_kwargs.setdefault("supports_check_mode", True)
    module = AnsibleModule(argument_spec=spec, **module_kwargs)
    try:
        result = run(module.params, client_from_module(module), module.check_mode)
    except ExosError as err:
        module.fail_json(msg=str(err), code=err.code, endpoint=err.endpoint)
    except ExosModuleError as err:
        module.fail_json(msg=str(err))
    module.exit_json(**result)
