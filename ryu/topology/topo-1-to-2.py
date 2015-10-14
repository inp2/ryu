from mininet.net import Mininet
from mininet.node import UserSwitch, Controller, RemoteController
from mininet.cli import CLI
from mininet.term import makeTerm

import os

net = Mininet(switch = UserSwitch)

h1 = net.addHost('h1', ip='10.0.0.1', mac="00:00:00:00:00:01")
h2 = net.addHost('h2', ip='10.0.0.2', mac="00:00:00:00:00:02")
client = net.addHost('client', ip='10.0.0.3', mac="00:00:00:00:00:03")

s1 = net.addSwitch('s1')

net.addLink(s1, h1)
net.addLink(s1, h2)
net.addLink(s1, client)

c0 = net.addController('c0', controller=RemoteController)

net.start()
makeTerm(h1)
makeTerm(h2)
#h1.cmdPrint('python echo_server.py 80 > h1.txt')
makeTerm(client)

CLI(net)

net.stop()
os.system("sudo mn -c")
