# Changelog

## 0.2.0

The collection now covers most of what an `admin` login can change in the router's own page.
The README lists what is left out, and which paths were run against a real router.

New modules: `upnp`, `firewall`, `firewall_rule`, `dmz`, `port_forward`, `dns_host_mapping`,
`arp_spoofing`, `controls`, `device`, `access_schedule`, `service_blocking_rule`,
`service_blocking`, `ipv6_lan`, `dhcp`, `wifi_network`, `wifi_secondary_network`, `wifi_radio`,
`ping`, `traceroute`, `backup`, `reboot`.

`info`:

- New subsets `dhcp`, `ports`, `radios`, `firewall_rules`, `dns_host_mappings`, `ddns`,
  `arp_spoofing`, `controls`, `ipv6_lan`, `access_schedules`, `service_blocking`, `internet`.
- `security.port_forwards` is now a list of rules with the keys `port_forward` returns. 0.1.x
  failed on a router that had a rule.
- `security.dmz_host` is the host when one is set (the router reports it as `1|<host>`, now
  confirmed).

Other:

- A failure message now carries the router's own wording for an `#ERROR_nnn` reply.
- A flag the router reports in a spelling the collection does not know is an error, not "off".
- `timeout` now defaults to 30 seconds (was 15). The router's web server stops answering for
  around 15 seconds after some changes, which made tasks fail now and then.
- `module_defaults` group `workshop144.calix_exos.all`.
- Every module was run against a GS4227 and a GS4227W on EXOS 25.4.0; the README says what
  each live run did and did not exercise.

## 0.1.1

- `info`: a guest Wi-Fi network's `hidden` and `isolation` are now null, because the router does
  not report them for a guest network; 0.1.0 returned false. New keys `network_type` and
  `gateway` on every Wi-Fi entry (`guest` and the guest subnet's gateway, or null).

## 0.1.0

First release.

- `workshop144.calix_exos.info`: read a router's system, LAN, DHCP reservation, client, Wi-Fi,
  security and WAN state.
- `workshop144.calix_exos.dhcp_reservation`: add or remove one DHCP reservation.
- Unit tests, a live smoke test (`tests/live/`) and notes on the router's interface
  (`docs/api-notes.md`).

Tested on a GS4227 and a GS4227W, both running EXOS 25.4.0, with the live smoke test.
