#!/usr/bin/env python3


'''
--DHCP fingerprinting: option order, vendor class, hostname — maps to device class (e.g. Fingerbank “Wi‑Fi router”) when DHCP is visible on the LAN.

Option Order: The DHCP protocol has various "options" (fields of data). Different operating systems list these options in a specific, unique sequence. A Windows laptop lists them differently than a Nintendo Switch.

Vendor Class (Option 60): This is a string of text that often explicitly names the manufacturer or the operating system (e.g., dhcpcd-5.5.6 or MSFT 5.0).

Hostname: The name you gave your device, like "Mike's-iPhone." Even the way this name is formatted can hint at the device type.
TODO: implement DHCP fingerprinting using option order, vendor class, and hostname to identify device types on the network.


'''