"""This script is designed to intercept SSL
packets coming into the device and to warn
the user if the Heartbleed bug is being exploited.This script is for educational use only and is
property of Jamie Coupe"""

# Import scapy and scapy ssl-tls layers
from scapy.all import *
from scapy.layers.ssl_tls import *

# Function for checking fields
def field_comparison(pkt):

    if pkt[]: 
        return pkt[]

# Ask user how many packets they want
pktC = int(raw_input("Please enter how many packets you wish to capture:"))

# Intercept Network Traffic
pkt = sniff(lfilter=lambda x: x.haslayer(ARP), count=pktC)

# Display the sniffed packets
pktI = 0

while pktI < pktC:

    # Print the packets
        print pkt[pktI].summary()
        print pktI
        pktI += 1
