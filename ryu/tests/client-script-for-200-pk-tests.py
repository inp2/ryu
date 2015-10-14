import sys
import socket
import time
import itertools
import random

ipv4_h = ['10.0.0.1', '10.0.0.2', '10.0.0.1']

pl_1 = [5123]
pl_2 = [5123, 6234]
pl_3 = [5123, 6234, 7345]
pl_4 = [5123, 6234, 7345, 8456]
final_port = 2000

sleep_time = 0.15

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = "0123456789"
host_flag = True

pl_len = int(sys.argv[1])
knock_count = int(sys.argv[2])
port_list = []

if pl_len == 1:
	port_list = pl_1
elif pl_len == 2:
	port_list = pl_2
elif pl_len == 3:
	port_list = pl_3
elif pl_len == 4:
	port_list = pl_4


print ( "port sequence : %s" % port_list )
print ("total knock tests: %d" % knock_count)
permutations = list(itertools.permutations(port_list))

def alternateHost():
	global host_flag
	host_flag = not host_flag
	if host_flag:
		return ipv4_h[0]
	else:
		return ipv4_h[1]

def sendUDP(msg, ip, port):
	sock.sendto(msg, (ip, port))
	time.sleep(sleep_time)

def portKnock(pl):
	# perform inermediate knocking
	for i in range(len(port_list)):
		sendUDP(msg, alternateHost(), pl[i])

	sendUDP(msg, ipv4_h[0], final_port)
	sendUDP(msg, ipv4_h[1], final_port)

def randPortList(permutations):
	return permutations[random.randrange(len(permutations))]

# knock the ports for knock_count times
for i in range(knock_count):
	portKnock(randPortList(permutations))

print "tests finished"
