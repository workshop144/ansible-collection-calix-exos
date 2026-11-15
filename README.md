# workshop144.calix_exos

Unofficial Ansible modules for Calix EXOS routers (the GigaSpire family), using the router's own
local web interface.

**This project is not affiliated with, endorsed by or supported by Calix.** There is no published
API for the local interface. What is here was worked out by watching what the router's own admin
page sends, on equipment the authors administer. It is tested on the GS4227 and GS4227W running
EXOS 25.4.0 and may stop working after a firmware update. Use it only on equipment you are
allowed to administer. Many of these routers are owned and managed by an internet provider, which
can overwrite local changes at any time.

## What it does

| Module | Purpose |
|---|---|
| `workshop144.calix_exos.info` | Read system, LAN, DHCP reservation, client, Wi-Fi, security and WAN state. Changes nothing. |
| `workshop144.calix_exos.dhcp_reservation` | Add or remove one DHCP reservation. |

Both support check mode, so a playbook run with `--check --diff` reports drift without changing
the router. Passwords and Wi-Fi keys are never returned.

## Install

In `requirements.yml`:

```yaml
collections:
  - name: https://github.com/workshop144/ansible-collection-calix-exos.git
    type: git
    version: v0.1.0
```

then `ansible-galaxy collection install -r requirements.yml`. Needs ansible-core 2.16 or later
and nothing else.

## Connecting

The modules run on the control node and talk HTTPS to the router, so use `connection: local`
(or `delegate_to: localhost`). There is no SSH on these routers.

| Option | Default | Notes |
|---|---|---|
| `host` | required | Name or address of the router. |
| `username` | `admin` | |
| `password` | required | Never logged. Falls back to the environment variable `CALIX_EXOS_PASSWORD`. |
| `validate_certs` | `false` | The router ships with a self-signed certificate. |
| `timeout` | `15` | Seconds per request. |

Each task logs in, does its work and logs out. A failed login is never retried, because the
router locks the account after repeated failures.

## Examples

```yaml
- name: Read the router
  workshop144.calix_exos.info:
    host: 192.0.2.1
    password: "{{ router_password }}"
  register: router

- name: UPnP must be off
  ansible.builtin.assert:
    that: not router.exos.security.upnp

- name: Reserve an address for the printer
  workshop144.calix_exos.dhcp_reservation:
    host: 192.0.2.1
    password: "{{ router_password }}"
    mac: "02:00:00:00:00:aa"
    ip: 192.0.2.150
```

## Development

The repository root is the collection root, so clone it to a path ending in
`ansible_collections/workshop144/calix_exos`. From there:

```
ansible-test sanity --venv
ansible-test units --venv -v
```

`tests/live/` holds a smoke test to run by hand against a real router; see its README.
`docs/api-notes.md` records what is known about the router's interface.

## Licence

GPL-3.0-or-later. See `LICENSE`.
