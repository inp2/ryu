import socket
import sys

ipv4_server = '10.0.0.1'
port_server = 80
times = 60
unit_time = 1

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = (ipv4_server, port_server)
sock.connect(server_address)
print >>sys.stderr, 'connecting to %s port %s' % server_address

i = 0
while i < times:
	 

