# Live tests

Playbooks that run the modules against a real router. Each one changes something, checks it,
and puts it back, also when a step fails. Run them only against a router you administer.

| Playbook | What it touches | Disturbs the network? |
|---|---|---|
| `info.yml` | nothing: reads every subset | no |
| `defaults.yml` | nothing: checks the `module_defaults` group | no |
| `smoke.yml` | a DHCP reservation for a made-up MAC | no |
| `settings.yml` | UPnP, DMZ host, a port forward, a DNS name, ARP spoofing protection, LED, SIP ALG | no |
| `tools.yml` | firewall level and stealth mode, a custom firewall rule, a device name, ping, traceroute, backup | briefly lowers the firewall level |
| `parental.yml` | an access schedule and a blocked service for made-up devices, IPv6 LAN settings | IPv6 addressing may renew |
| `network.yml` | DHCP lease time, one radio setting, a temporary guest network, the primary network's hidden flag | **yes**: Wi-Fi devices can drop for some seconds, several times |
| `reboot.yml` | restarts the router | **yes**: offline for a few minutes |

From the collection root:

```
CALIX_EXOS_PASSWORD='...' ansible-playbook tests/live/info.yml -e exos_host=192.0.2.1
```

The collection must be where Ansible can find it, for example by setting
`ANSIBLE_COLLECTIONS_PATH` to the directory that holds `ansible_collections/`.

`network.yml` and `reboot.yml` should be run from a machine that does not depend on the router
under test for its own connection, so that the run can finish and put things back.
