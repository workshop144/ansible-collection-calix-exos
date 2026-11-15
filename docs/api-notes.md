# Notes on the EXOS local web interface

Calix does not publish an API for the router's local admin page. These notes record what was
observed by watching the page's own requests on a GS4227 and a GS4227W running EXOS 25.4.0. They
are incomplete and may be wrong for other models or firmware. Every address, name and identifier
below is an example.

## Transport

- HTTPS on port 443 with a self-signed certificate. Port 80 redirects to 443.
- No SSH or telnet service answers on the LAN side.
- Every request is a `POST` with a form-encoded body. Most carry an `action` field.
- Replies are JSON, sometimes with spaces inside empty objects (`{ }`). Values are usually
  strings, including numbers and flags (`"1"`, `"0"`).

## Session

1. `POST /login_nonce.cmd` with an empty body returns a 64-character hex nonce as plain text.
2. `POST /login.cgi` with `Username`, `nonce` and `auth`, where
   `auth = sha256("<username>:<nonce>:<password>")` in hex. Success is HTTP 200 with an empty
   body and a cookie named `Authorization`. A refused login is a non-200 status.
3. `POST /get_access_status.cmd` with `Username` works without a session and returns the lockout
   counters, for example `{"user_type": 0, "status": 1, "count": 0, "total_count": 0, "locktime": 0}`.
   The router locks an account after repeated failed logins. Successful logins were not seen to
   count toward it.
4. `POST /logout.cgi` ends the session. The router then resets the connection, so the next
   request on it fails; that is normal.

A second login from another client did not end an existing browser session.

## Failures

- A request without a valid session is answered with HTTP 200 and the login page, for any path.
- An application error is HTTP 200 with a body `#ERROR_nnn`. Codes seen, meaning not known:

| Code | Seen when |
|---|---|
| `018` | `dhcpcfg.cmd` with `action=get` |
| `019` | `readOnly.cmd`, `mgmtprotocol.cmd`, `advanced_remote_management.cmd` with `action=get` |
| `052` | `wlinfo.cmd` with `action=get` |
| `078` | `software.cmd`, `tr069.cmd`, `upgrade_history.cmd` with `action=get`; `ssh_seed.cmd` |

- An empty body is a normal reply to a write, and to a read that has nothing to list.

## Reads this collection uses

| Endpoint | Fields | Reply |
|---|---|---|
| `status_system.cmd` | `action=get` | `system_info`: list of `{param, value}` rows (`Model Number`, `FSAN`, `Serial Number`, `Host Name`, `Device Uptime`, `EXOS Version`, `Operational Mode`, `Operational Role`); also `cpu_info`, `mem_info`, `space_info` |
| `cgi_parameter_value.cmd` | `action=get`, `ejGetVal=<comma-separated names>` | one string per name; an unknown name gives `{ }` |
| `dhcp_reservation.cmd` | `action=init` | `networks`: list of `{network, dhcpPool, dhcpEnbled, dhcpStart, dhcpEnd}`; `staticIpLease`: list of `{dhcpPool, ip, mac}` |
| `device_table.cmd` | `action=get` | `ipv4` and `ipv6` lists of `{dhcpPool, macAddress, ipAddress, interfaceType, isActive, deviceName, type, fingerPrint}`; `active_count` |
| `wlinfo.cmd` | `action=get_status` | list of `{radioid, ifaceid, ssid, broadcast, radio, state, mode, frequency, channelMode, channel, secured, secureType, MACAuthFilter, wps, wpsType, ...}` |
| `wlinfo.cmd` | `action=get_ssid_setup`, `wlSsidUsage=primary` or `guest` | list of `{wlRadioIdx, wlBand, wlRadioEnbl, wlSsidIdx, wlSsid, wlHidden, wlEnbl, wlAPIsolation, l2bridge, wlAuthMode, nonce, wlWpaPsk}`. `nonce` and `wlWpaPsk` are key material and are dropped by this collection |
| `scdmz.cmd` | `action=get` | empty when no DMZ host is set |
| `portForwardingAssociations.cmd` | `action=readall` | empty when nothing is forwarded |
| `status_connection.cmd` | `action=getStatus` | `connection`: `{wan, ipv4, ipv6}` each `{state, color}`; `gateway` |

Parameter names known to work with `cgi_parameter_value.cmd`: `ethIpAddress`, `ethSubnetMask`,
`enblDhcpSrv`, `dhcpEthStart`, `dhcpEthEnd`, `dhcpSubnetMask`, `dhcpLeasedTime`, `enblUpnp`,
`enblUpnpnat`, `fwLevel`, `fwStealthMode`, `dmzHost`.

## Writes this collection uses

| Endpoint | Fields | Effect |
|---|---|---|
| `dhcpdstaticlease.cmd` | `action=add`, `dhcpPool`, `mac`, `static_ip` | adds a reservation; empty reply |
| `dhcpdstaticlease.cmd` | `action=remove`, `rmLst=<ip>` | removes the reservation for that address; empty reply |

The default pool is called `lan`. MAC addresses come back lower-case and colon-separated.

## Other things noticed

- `backupsettings.conf` downloads a configuration backup. It has a one-line plain header and an
  opaque body; it is not readable as settings.
- Wi-Fi Protected Setup is reported per network as `wps` with `wpsType` `PushButton`. The admin
  page has no switch to turn it off.
- Many routers of this kind are managed remotely by the internet provider, which can change
  settings independently of anything done through the local interface.
