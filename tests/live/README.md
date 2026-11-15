# Live smoke test

`smoke.yml` runs both modules against a real router. It adds a reservation for a made-up MAC
address (`02:00:00:00:00:01`) on a free address in the DHCP pool, checks that a second run
changes nothing, removes it again and checks that the table is back as it was. It removes the
made-up entry even if a step fails.

Run it only against a router you administer. From the collection root:

```
CALIX_EXOS_PASSWORD='...' ansible-playbook tests/live/smoke.yml -e exos_host=192.0.2.1
```

The collection must be where Ansible can find it, for example by setting
`ANSIBLE_COLLECTIONS_PATH` to the directory that holds `ansible_collections/`.
