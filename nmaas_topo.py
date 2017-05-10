from functools import partial
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.util import dumpNodeConnections

 #
 #        h4 h5   h6
 #         \/     |
 #       --s3-----s4--
 #      /  | \   /|   \
 # h7--s5  |   X  |    s6--h8
 #      \  | /   \|   /
 #       --s2-----s1--
 #         /\     |
 #        h2 h3   h1
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
        h6 = self.addHost("h6", ip="10.0.0.6", mac="00:00:00:00:00:06")
        h7 = self.addHost("h7", ip="10.0.0.7", mac="00:00:00:00:00:07")
        h8 = self.addHost("h8", ip="10.0.0.8", mac="00:00:00:00:00:08")

        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", protocols="OpenFlow13")
        s3 = self.addSwitch("s3", protocols="OpenFlow13")
        s4 = self.addSwitch("s4", protocols="OpenFlow13")
        s5 = self.addSwitch("s5", protocols="OpenFlow13")
        s6 = self.addSwitch("s6", protocols="OpenFlow13")



        self.addLink(s1, h1,delay='10ms')
        self.addLink(s2, h2, delay='5ms')
        self.addLink(s2, h3, delay='1ms')
        self.addLink(s1, s2, delay='2ms')
        self.addLink(s2, s3, delay='20ms')
        self.addLink(s3, h4, delay='1ms')
        self.addLink(s3, h5, delay='1ms')
        self.addLink(s1,s4, delay='1ms')
        self.addLink(s4, s3, delay='1ms')
        self.addLink(s4, h6, delay='1ms')
        # -- new topology
        #    -- cross links in the middle
        self.addLink(s1, s3, delay='1ms')
        self.addLink(s2, s4, delay='1ms')
        # -- the two new switches on the left and on the right
        self.addLink(h7, s5, delay='1ms')
        self.addLink(s5, s3, delay='1ms')
        self.addLink(s5, s2, delay='1ms')
        self.addLink(h8, s6, delay='1ms')
        self.addLink(s6, s4, delay='1ms')
        self.addLink(s6, s1, delay='1ms')

