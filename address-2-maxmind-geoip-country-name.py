#!/usr/bin/env python

# push IPv4 addresses to this via pipe to get country NAME on stdout

import pygeoip
import sys

g = pygeoip.GeoIP('GeoIP.dat', pygeoip.MEMORY_CACHE)

for address in sys.stdin:
   # skip header lines
   if not '.' in address:
       continue
   address = address.strip()
   print g.country_name_by_addr(address)

