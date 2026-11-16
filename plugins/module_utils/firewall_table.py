# -*- coding: utf-8 -*-
# Copyright (c) Workshop 144
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""The firewall levels as the router's admin page defines them (EXOS 25.4.0).

For each service, whether a level blocks it inbound and outbound. The page sends the whole table
with the level, in this order, so the module does too."""

from __future__ import annotations

# name, (low in, low out), (medium in, medium out), (high in, high out); 1 blocks
SERVICES = (
    ("directx", (0, 0), (1, 0), (1, 0)),
    ("stb1", (0, 0), (0, 0), (0, 0)),
    ("stb2", (0, 0), (0, 0), (0, 0)),
    ("stb3", (0, 0), (0, 0), (0, 0)),
    ("dns", (0, 0), (0, 0), (1, 0)),
    ("ftp", (0, 0), (1, 0), (1, 0)),
    ("ftps", (0, 0), (1, 0), (1, 0)),
    ("gmail", (0, 0), (1, 0), (1, 0)),
    ("h323", (0, 0), (1, 0), (1, 0)),
    ("http", (0, 0), (1, 0), (1, 0)),
    ("https", (0, 0), (1, 0), (1, 0)),
    ("icmp1", (0, 0), (0, 0), (0, 0)),
    ("icmp2", (0, 0), (0, 0), (0, 0)),
    ("icmp3", (0, 0), (0, 0), (0, 0)),
    ("icmp4", (0, 0), (0, 0), (0, 0)),
    ("imap", (0, 0), (1, 0), (1, 0)),
    ("imaps", (0, 0), (1, 0), (1, 0)),
    ("ipp", (0, 0), (1, 0), (1, 0)),
    ("ipsec", (0, 0), (1, 0), (1, 0)),
    ("irc", (0, 0), (1, 0), (1, 0)),
    ("l2tp", (0, 0), (1, 0), (1, 0)),
    ("msn_gaming", (0, 0), (1, 0), (1, 0)),
    ("mysql", (0, 0), (1, 0), (1, 0)),
    ("nntp", (0, 0), (1, 0), (1, 0)),
    ("NTP", (0, 0), (1, 0), (1, 0)),
    ("oracle", (0, 0), (1, 0), (1, 0)),
    ("pcanywhere", (0, 0), (1, 0), (1, 0)),
    ("pptp", (0, 0), (1, 0), (1, 0)),
    ("pop3", (0, 0), (1, 0), (1, 0)),
    ("pop3s", (0, 0), (1, 0), (1, 0)),
    ("ps23", (0, 0), (1, 0), (1, 0)),
    ("rip", (0, 0), (1, 0), (1, 0)),
    ("realav", (0, 0), (1, 0), (1, 0)),
    ("realserver", (0, 0), (1, 0), (1, 0)),
    ("rtp", (0, 0), (1, 0), (1, 0)),
    ("sftp", (0, 0), (1, 0), (1, 0)),
    ("sip", (0, 0), (0, 0), (1, 0)),
    ("sling", (0, 0), (1, 0), (1, 0)),
    ("smtp", (0, 0), (1, 0), (1, 0)),
    ("SQL", (0, 0), (1, 0), (1, 0)),
    ("ssh", (0, 0), (1, 0), (1, 0)),
    ("t120", (0, 0), (1, 0), (1, 0)),
    ("telnet", (0, 0), (1, 0), (1, 0)),
    ("vnc", (0, 0), (1, 0), (1, 0)),
    ("wm", (1, 0), (1, 0), (1, 0)),
    ("ws", (1, 0), (1, 0), (1, 0)),
    ("xbox", (0, 0), (1, 0), (1, 0)),
    ("xbox2", (0, 0), (1, 0), (1, 0)),
    ("xbox3", (0, 0), (1, 0), (1, 0)),
    ("xboxk", (0, 0), (1, 0), (1, 0)),
    ("yahoo", (0, 0), (1, 0), (1, 0)),
    ("all_other_ports", (0, 0), (1, 0), (1, 0)),
)

LEVELS = {"off": "Basic", "low": "Low", "medium": "Medium", "high": "High"}
COLUMN = {"Low": 1, "Medium": 2, "High": 3}


def firewall_info(level):
    """The ``firewallInfo`` field for a level name as the router spells it."""
    parts = []
    for row in SERVICES:
        inbound, outbound = row[COLUMN[level]] if level in COLUMN else (0, 0)
        parts.append("%s_in:%d|%s_out:%d" % (row[0], inbound, row[0], outbound))
    return "|".join(parts)
