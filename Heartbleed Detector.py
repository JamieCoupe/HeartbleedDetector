"""This script is designed to intercept SSL
packets coming into the device and to warn
the user if the Heartbleed bug is being exploited.This script is for educational use only and is
property of Jamie Coupe"""

# Import Socket module
from scapy.all import *
from scapy.layers.ssl_tls import *

#Function for checking fields
def field_comparison(pkt):
    if pkt[ARP].op == 1:  # who-has (request)
        return 'Request: {} is asking about {}'.format(pkt[ARP].psrc, pkt[ARP].pdst)
    if pkt[ARP].op == 2:  # is-at (response)
        return '*Response: {} has address {}'.format(pkt[ARP].hwsrc, pkt[ARP].psrc)

# Intercept Network Traffic
pkt = sniff(prn=field_comparison , count=10)



# Compare Size and Length Fields
# Repeat if packet is not malicious

# If Malicious packet > Alert/Drop connection
#This can be done with the stop_filter in sniff function. need to define function