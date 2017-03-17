from functools import partial
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.util import dumpNodeConnections


class NMaaSTopo(Topo):
    def __init__(self):
        '''
        Create custom nmaas topo
        '''

        Topo.__init__(self)

        #add hosts
        h1 = self.addHost("h1", ip="10.0.0.1", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", ip="10.0.0.3", mac="00:00:00:00:00:03")
        h4 = self.addHost("h4", ip="10.0.0.4", mac="00:00:00:00:00:04")
        h5 = self.addHost("h5", ip="10.0.0.5", mac="00:00:00:00:00:05")

        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", protocols="OpenFlow13")
        s3 = self.addSwitch("s3", protocols="OpenFlow13")


        self.addLink(s1,h1,delay='10ms')
        self.addLink(s2, h2, delay='5ms')
        self.addLink(s2, h3, delay='1ms')
        self.addLink(s1, s2, delay='2ms')
        self.addLink(s2, s3, delay='20ms')
        self.addLink(s3, h4, delay='1ms')
        self.addLink(s3, h5, delay='1ms')
        self.addLink(s1,s3, delay='1ms', loss=50)

