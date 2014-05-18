#!usr/bin/env python
#
# DNSChain - Distributed Blockhain-based DNS server and client
# Copyright (C) 2014 mtanous22@gmail.com
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

import re

# Format for types is [type value, max rdlength, format]
RRTYPES = {'A': [1, 4, 'IPV4']}  # TODO : Add record types when support is added


class RecordException(Exception):
    """ Thrown when there's a problem building a domain name record """

    def __init__(self, msg):
        self.msg = msg


def verify_domain_valid(dname):
    # TODO : Verify domain name does not already have associated record
    if len(dname) > 255:
        raise RecordException("Domain name exceeds 255 octet maximum limit.")


def verify_rdata_valid(rtype, data):
    if len(data) > RRTYPES[rtype][1] * 8:  # Multiply value by 8 to obtain value in octets
        raise RecordException("Data is longer than expected length of " + str(RRTYPES[rtype][1]) + " bytes.")

    if rtype == 'A':
        ip_valid = re.search(r'\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\Z', str(data))
        if ip_valid is None:
            raise RecordException("Data for type A record not a valid IPV4 address.")


def create_dns_record(domain_name, record_type, ttl, data):
    if record_type not in RRTYPES:
        raise RecordException("Invalid record type requested. May currently be unsupported.")

    # Verify inputs are valid for creation of DNS record
    if ttl.bit_length() > 32:
        raise RecordException("TTL value must be representable as a signed 32 bit integer.")
    verify_domain_valid(domain_name)
    # Pad domain name out to maximum length of 255 octets
    # Is this padding necessary? Will need to check
    domain_name = domain_name.ljust(255)
    rdata = bytearray(data)
    verify_rdata_valid(record_type, rdata)

    # Build byte array construction containing DNS record
    # Start with padded domain name (will just be domain name if padding is not needed)
    record = bytearray(domain_name)

    # Append record type value
    type_val = RRTYPES[record_type][0]
    type_hval = _to_hex(type_val)
    if 8 < type_val.bit_length() <= 16:
        print 'Appending type val: 0x' + type_hval.encode('hex')
    elif type_val.bit_length() <= 8:
        print 'Appending type val: 0x00' + type_hval.encode('hex')
        record.append('\x00')
    else:
        raise RecordException("Incorrect bit size for record type value (max 2 bytes)")
    for h in type_hval:
            record.append(h)

    # Append class value for internet (always 1) - other types not supported or deprecated
    record.append('\x00')
    record.append('\x01')

    # Append TTL value to data construct
    if ttl.bit_length() <= 24:
        record.append('\x00')
        if ttl.bit_length() <= 16:
            record.append('\x00')
            if ttl.bit_length() <= 8:
                record.append('\x00')
    for h in _to_hex(ttl):
        record.append(h)

    # Append data length
    dlength = RRTYPES[record_type][1]
    h_dlength = _to_hex(dlength)
    if dlength.bit_length() <= 8:
        record.append('\x00')
    for h in h_dlength:
        record.append(h)

    # Append data
    for c in rdata:
        record.append(c)

    return record


def _to_hex(int_value):
    encoded = format(int_value, 'x')

    length = len(encoded)
    encoded = encoded.zfill(length + length % 2)

    return encoded.decode('hex')


def parse_dns_record(drecord):
    domain = str(drecord[:255]).rstrip()
    type_value = str(drecord[255:257]).encode('hex')
    # class_value = drecord[257:259]  - not needed as will always be 1 for Internet
    ttl_value = str(drecord[259:263]).encode('hex')
    data_length = str(drecord[263:265]).encode('hex')
    data = str(drecord[265:])

    return domain, type_value, ttl_value, data_length, data


# DEBUG SCRIPT
if __name__ == '__main__':
    import sys
    domain = "codinganarchy.net"
    try:
        r = create_dns_record(domain, 'A', 0x2400, '127.0.0.1')
    except RecordException as err:
        print err.msg
        sys.exit()
    # print r
    print "Length of record (in bytes): " + str(len(r))

    domain, rtype, ttl_val, rdlength, rdata = parse_dns_record(r)

    print "Domain name: " + domain
    print "Type value: " + rtype
    print "TTL value: " + ttl_val
    print "Data field length: " + rdlength
    print "Data: " + rdata


