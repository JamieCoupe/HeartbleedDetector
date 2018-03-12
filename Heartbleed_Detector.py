"""This script is designed to intercept SSL
packets coming into the device and to warn
the user if the Heartbleed bug is being exploited.This script is for educational use only and is
property of Jamie Coupe"""

# Import scapy and scapy ssl-tls layers
from scapy.all import *
from scapy.layers.scapy_ssl_tls.ssl_tls import *


# Function to check if message is a heartbeat message
def is_heartbeat(p):
    if p[SSL][TLSRecord].content_type == 24:
        return True

    else:
        return False


# Function to get length of heartbeat message
def get_length(p):

    length = p[SSL][TLSRecord].length
    return length


# Function to get actual length of heartbeat message
def get_actual_length(p):

    # Set data field to data value
    raw_hex = [pkt[2][SSL][TLSRecord]]
    data = str(raw_hex)
    processed_data = data[92:94] + data[96:98]
    return int("0x" + processed_data, 0)


# Function for checking fields
def field_comparison(p):

    if is_heartbeat(p):

        if get_length(p) != get_actual_length(p):
            print "This packet is possibly malicious, now dropping connection"
            return 1

        else:
            print "The packet is not malicious"
            return 0


# Intercept Network Traffic
pkt = sniff(iface="eth1", lfilter=lambda x: x.haslayer(TLSRecord), stop_filter=field_comparison)


# Display all the sniffed packets
"""i = 0

while i < 3:
    # Print the packets
    print "<<New Packet>>"
    print "Length = " + str(pkt[i][SSL][TLSRecord].length)
    print pkt[i][SSL][TLSRecord].show()

    i += 1"""

# Display the heartbeat request
"""print "<<Heartbeat Request>>"
print get_length(pkt[2])
print get_actual_length(pkt[2])"""

field_comparison(pkt[2])

# If Malicious packet > Alert/Drop connection
# This can be done with the stop_filter in sniff function. need to define function
