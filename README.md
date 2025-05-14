# Netdiscover
by Jaime Penalba <jpenalbae@gmail.com>

Welcome to official Netdiscover repository (since  Feb. 05, 2019).

Netdiscover is a network address discovering tool, developed mainly for those
wireless networks without dhcp server, it also works on hub/switched networks.
Its based on arp packets, it will send arp requests and sniff for replies.

Its my first public C tool, so don't be too hard with me, if some parts on the
code looks like obfuscated or are unreadable, and feel free to send suggestions
to https://github.com/netdiscover-scanner/netdiscover/issues or patches (PR) to
https://github.com/netdiscover-scanner/netdiscover/pulls.

Also notify me for any bug or compilation error, it must compile with gcc 2.95
or newer.

An excessive CPU consumption happens on OpenBSD, due to threads design and the
use of pcap_open_live() with pcap_loop(), any suggestions for fix are welcome.


## Requirements

 - libpcap
 - libnet > 1.1.2


## Build

```
$ ./update-oui-database.sh (optional, to update the MAC addresses list)
$ ./autogen.sh
$ ./configure
$ make
# make install
```

To return to original source code, you can use '$ make distclean' command.


## Bugs & Contact

Feel free to notify me about any problem, bug, suggestions or fixes at:
https://github.com/netdiscover-scanner/netdiscover/issues or
https://github.com/netdiscover-scanner/netdiscover/pulls
