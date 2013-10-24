#!/usr/bin/env python

# Author: Chuck King
# Date: 2013-10-23
# Reason: Pull some non-deterministic self-signed certificate info
# from the Project Sonar Internet-wide scan port 443 cert files.

### License ###
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
### License ###

import base64
import bz2file # bz2 will not read a multi-stream pbzip2 file
import glob
import json
import OpenSSL
import sys

# cert files we want to process
FILE_GLOB = "20130910_ssl_certs_*"

line_counter = 0
error_counter = 0
ssc_line_counter = 0
ssc_parse_error_counter = 0 

# keep track of IPv4 first quad numbers
first_quads = dict()
# load up the dict so we'll have representation for all quads in output
for i in range(257):
    first_quads[i] = 0

try:
    cert_f = open('z-ssc-hostIp-commonName-organizationName.txt', 'w')
except Exception as e:
    print e

try:
    log_f = open('z-ssc-log.txt', 'w')
except Exception as e:
    print e

def processLine(jsonline):

    global error_counter, ssc_line_counter, ssc_parse_error_counter

    try:
        data = json.loads(jsonline)
    except Exception as e:
        print >>sys.stderr, "ERROR: Could not load json on line %d" % line_counter
        print >>sys.stderr, "Exception: %s" % e
        print >>sys.stderr, "%s" % jsonline
        error_counter += 1
        return 

    if not data['host_ip']:
        print >>sys.stderr, "ERROR: Record has no IPv4 host_ip on line %d" % line_counter
        error_counter += 1 
        return

    first_quad = data['host_ip'].split('.')[0]
    first_quad = int(first_quad)
    if not 0 <= first_quad <= 65535:
        print >>sys.stderr, "ERROR: Address first quad not 0-65535 on line %d" % line_counter
        error_counter += 1 
        return

    # keep track of the count
    if first_quad not in first_quads:
        first_quads[first_quad] = 0
    else:
        first_quads[first_quad] += 1

    if not data['cipher']:
        print >>sys.stderr, "ERROR: Found null cipher on line %d" % line_counter
        error_counter += 1 
        return

    # there may be a cert to CA chain so grab the first cert
    cert = data['certs'][0]

    try:
        cert = base64.b64decode(cert)
    except:
        print >>sys.stderr, "ERROR: Could not base64 decode cert on line %d" % line_counter 
        error_counter += 1 
        return
        
    try:
        x = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
    except:
        print >>sys.stderr, "ERROR: Could not parse x509 cert on line %d" % line_counter 
        error_counter += 1 
        return

    try:
        if x.get_subject().organizationName == x.get_issuer().organizationName: 
            ssc_line_counter += 1 
            try:
                msg = "%s|%s|%s\n" % ( data['host_ip'], x.get_subject().commonName, 
                                      x.get_subject().organizationName )
                cert_f.write(msg)
            except:
                print >>sys.stderr, "ERROR: Could not write ssc data on line %d" % line_counter 
                ssc_parse_error_counter += 1 
    except:
        print >>sys.stderr, "ERROR: Could not read ssc x509 data on line %d" % line_counter 
        error_counter += 1 
        return


# push headers to file
cert_f.write("Self-signed Certificates\n")
cert_f.write("Host IP|Subject Common Name|Subject Organization Name\n")

# read all the cert files
for bz2filename in glob.glob(FILE_GLOB):
    print >>sys.stderr, "######################################################################"
    print >>sys.stderr, "#### Processing %s" % bz2filename
    print >>sys.stderr, "######################################################################"
    print >>sys.stderr, "Currently at line count of %d" % line_counter
    for jsonline in bz2file.BZ2File(bz2filename):
        line_counter += 1
        processLine(jsonline)

print >>sys.stderr, "Lines processed: %d" % line_counter
log_f.write("Lines processed: %d\n" % line_counter)

print >>sys.stderr, "Lines skipped due to errors: %d" % error_counter
log_f.write("Lines skipped due to errors: %d\n" % error_counter)

print >>sys.stderr, "SSC lines processed: %d" % ssc_line_counter
log_f.write("SSC lines processed: %d\n" % ssc_line_counter)

print >>sys.stderr, "SSC parse errors: %d" % ssc_parse_error_counter
log_f.write("SSC parse errors: %d\n" % ssc_parse_error_counter)

with open('z-ssc-first-quad-counts-quad-count', 'w') as quad_f:
    for k,v in sorted(first_quads.items()):
        quad_f.write("%s|%d\n" % (k,v))
