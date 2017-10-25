#!/usr/bin/env python

# Two ways of querying a specific nameserver.

# from __future__ import print_function

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query


import dns.resolver

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ['60.6.14.95']
print(resolver.ednsflags)
print(resolver.flags)
answer = resolver.query('VERSION.BIND', rdtype=dns.rdatatype.TXT, rdclass=dns.rdataclass.CH)
print('The nameservers are:')

print(resolver.ednsflags)
print(resolver.flags)
print(type(answer))
for rr in answer:
    print(type(rr))
    print(rr.strings )

# This way is just like nslookup/dig:
# raw payload

qname = dns.name.from_text('amazon.com')
q = dns.message.make_query(qname, dns.rdatatype.NS)
print('The query is:')
print(q)
print('')
r = dns.query.udp(q, '8.8.8.8')

print('The response is:')
print(r)
print('')
print('The nameservers are:')
ns_rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS)
for rr in ns_rrset:
    print(type(rr))
    print(rr.target)
print('')
print('')

# # A higher-level way 
### easy to query

import dns.resolver

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ['8.8.8.8']
answer = dns.resolver.query('amazon.com', 'NS')
print('The nameservers are:')
for rr in answer:
    print(rr.target)



##################### find any rdata by building raw payload
print "*"*50
import dns.name
import dns.message
import dns.query
import dns.flags

domain = 'google.com'
name_server = '8.8.8.8'
ADDITIONAL_RDCLASS = 65535

domain = dns.name.from_text(domain)
if not domain.is_absolute():
    domain = domain.concatenate(dns.name.root)

request = dns.message.make_query(domain, dns.rdatatype.ANY)
request.flags |= dns.flags.AD
print request.flags
request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,
                   dns.rdatatype.OPT, create=True, force_unique=True)
response = dns.query.udp(request, name_server)
print (dns.flags.QR |dns.flags.RA) 
print (dns.flags.QR |dns.flags.RA) & response.flags == (dns.flags.QR |dns.flags.RA)
print "lalal"
print response.flags


############### find dns server version by building raw payload

domain = 'VERSION.BIND'
name_server = '60.6.14.95'
ADDITIONAL_RDCLASS = 65535

domain = dns.name.from_text(domain)
if not domain.is_absolute():
    domain = domain.concatenate(dns.name.root)

request = dns.message.make_query(domain, rdtype=dns.rdatatype.TXT, rdclass=dns.rdataclass.CH)
request.flags |= dns.flags.RA


response = dns.query.udp(request, name_server)

ns_rrset = response.find_rrset(response.answer, domain, dns.rdataclass.CH, dns.rdatatype.TXT)
for rr in ns_rrset:
    print type(rr)
    print rr

print (dns.flags.QR |dns.flags.RA) & response.flags == (dns.flags.QR |dns.flags.RA)
