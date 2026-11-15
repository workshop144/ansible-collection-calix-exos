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

Parameter names known to work with `ejGetVal`: `ethIpAddress`, `ethSubnetMask`, `enblDhcpSrv`,
`dhcpEthStart`, `dhcpEthEnd`, `dhcpSubnetMask`, `dhcpLeasedTime`, `enblUpnp`, `enblUpnpnat`,
`fwLevel`, `fwStealthMode`.

Some names are returned only when asked for in a second field, `ejGetOtherVal`, which is how the
admin page reads them: `dmzHost` is one (it is silently left out of an `ejGetVal` reply). Its
value is `0|` when no DMZ host is set. The value with one set has not been observed; this
collection assumes `1|<host>` and returns anything else unchanged.

## Writes this collection uses

| Endpoint | Fields | Effect |
|---|---|---|
| `dhcpdstaticlease.cmd` | `action=add`, `dhcpPool`, `mac`, `static_ip` | adds a reservation; empty reply |
| `dhcpdstaticlease.cmd` | `action=remove`, `rmLst=<ip>` | removes the reservation for that address; empty reply |

A guest network's `get_ssid_setup` row (with `wlSsidUsage=guest`) has a different shape: no
`wlBand`, `wlHidden` or `wlAPIsolation`, and instead `networkType` (`guest`), `bandFlag`,
`wlSubnet`, `wlGateway`, `wlMask`, `wlStartIp`, `wlEndIp`.

The default pool is called `lan`. MAC addresses come back lower-case and colon-separated.

## Other things noticed

- `backupsettings.conf` downloads a configuration backup. It has a one-line plain header and an
  opaque body; it is not readable as settings.
- Wi-Fi Protected Setup is reported per network as `wps` with `wpsType` `PushButton`. The admin
  page has no switch to turn it off.
- Many routers of this kind are managed remotely by the internet provider, which can change
  settings independently of anything done through the local interface.

## More of the interface (0.2.0)

Two request formats. Most endpoints take form fields. These take a JSON body with
`Content-Type: application/json`: `advanced_controls.cmd`, `arp_spoof.cmd`, `advfw_load.cmd`,
`advfw_apply.cmd`, `ddnsmngr.cmd`, `lan_setting_ipv6.cmd`, `xlan.cmd`, `detail_access.cmd`,
`wireless_radiosetup.wl`, `wps.cmd`.

Some replies are plain text, not JSON: `portForwardingAssociations.cmd` (records joined by `|`,
seven comma-separated fields each), `serviceBlockingRules.cmd` (`name,isCustom,entries`, entries
joined by `;`, each `PROTO:start:end:1`), `serviceBlockingAssociations.cmd` (`ip,rule`).

Secrets. A Wi-Fi key (and a dynamic DNS password) is sent and returned encrypted: each character
is XORed with the bytes of `sha256("<a>:<nonce>:<b>")` in turn and written as two hex digits.
For a Wi-Fi key `a` is the network name and `b` its security mode as the router spells it; the
nonce for a write comes from `get_nonce.cmd` and is sent along as `nonce`, and a read returns
the nonce it used in the row. This is obfuscation, not protection: anyone who can log in can
read the keys.

| Setting | Read | Write |
|---|---|---|
| UPnP | `cgi_parameter_value.cmd` `enblUpnp`, `enblUpnpnat` | `advanced_security_upnp.cgi` `enblUpnp`, `enblUpnpnat` (0/1) |
| Firewall level | `fwLevel` (`Basic`, `Low`, `Medium`, `High`), `fwStealthMode` | `advanced_firewallsettings.cmd` with `currentPage`, `fwLevel`, `fwStealthMode` and `firewallInfo`: the whole per-service table for the level |
| Custom firewall rules | `advfw_load.cmd` `["dsv4"]` (also `usv4`, `dsv6`, `usv6`) | `advfw_apply.cmd` `{"<chain>": [rules]}`: replaces the chain |
| DMZ host | `dmzHost` by `ejGetOtherVal`: `0|` or `1|<host>` | `scdmz.cmd` `action=add|remove`, `address` |
| Port forwards | `portForwardingAssociations.cmd` `readall` | `advancedPortForwarding.cmd` `add|remove` with `protocol`, `localIpAddress`, `localPortStart`, `localPortEnd`, `remoteIpAddress`, `remotePortStart`, `remotePortEnd` |
| DNS names | `dns_host_mapping.cmd` `loadTableData`: `[{ip, dns}]` | `add|del` with `hostName`, `ip`. The DNS service takes a few seconds to answer with a new name |
| ARP spoofing | `arp_spoof.cmd` `{"action":"get"}`: `{admin}` | `{"action":"set","admin":"1"|"0"}` |
| LED, SIP ALG | `advanced_controls.cmd` `{"action":"get","type":"all"}` | `{"action":"set","sip":0|1}`, `{"action":"set","led":0|1,"brightness":0-100}` |
| Devices | `device_table.cmd` `get` | `set` with `version=ipv4`, `mac`, `type`, `deviceName` |
| Access schedules | `scheduleAccessList` by `ejGetOtherVal`: `id/mac/days/start/end` joined by `|` | `detail_access.cmd` `{"action":"add","mac","username":<id>,"days":"Mon,Sat","start_time","end_time"}`, `{"action":"remove","username":<id>}` |
| Service blocking | `serviceBlockingRules.cmd`, `serviceBlockingAssociations.cmd` `readall` | `serviceBlockingRule.cmd` `add|remove` (`ruleName`, `protocol` `tcp|udp|tcpudp`, `portStart`, `portEnd`, `isCustom=1`), `serviceBlockingAssociation.cmd` `add|remove` (`ruleName`, `ipAddress`) |
| IPv6 on the LAN | `lan_setting_ipv6.cmd` `{"action":"load"}` | the same object back with `action=apply` |
| DHCP and LAN | `cgi_parameter_value.cmd` (see the names in `plugins/module_utils/settings.py`) | `dhcpcfg.cmd`, every field of the page at once |
| Radios | `wlinfo.cmd` `get_radio_setup` | `wireless_radiosetup.wl`: a JSON array, one object per band in the order 2.4, 5, 6 GHz, flags as `"1"`/`"0"` |
| Wi-Fi networks | `wlinfo.cmd` `get_ssid_setup` with `wlSsidUsage=primary|guest`, `get_pool_status` | `wireless_multiplessid.wl`. Primary: `wlSsidIdx`, `wlAuthMode`, `wlHidden`, `wlSsidSuffix=0`, `wlSsid`, `wlWpaPsk`, `nonce`. Secondary: the row plus `actiondo` (1 create, 2 edit, 0 remove) and `oldname` |
| Ping, traceroute | `ping_test.cmd`, `traceroute.cmd` `status` | `start_ping` / `trace`, then poll |
| Backup | GET `backupsettings.conf` | not covered |
| Reboot | | POST `rebootinfo.cgi` with no fields; `login_nonce.cmd` answers again after about a minute and a half |

Parental control pages are refused unless `apps_status.cmd` reports `scheduleType` `ewi`, and
website blocking is refused while the provider's security app runs.

The admin page's own text for each `#ERROR_nnn` code is in `plugins/module_utils/errors.py`.

