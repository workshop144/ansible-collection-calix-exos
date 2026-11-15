# Changelog

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
