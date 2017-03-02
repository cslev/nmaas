
from mininet.node import CPULimitedHost, Host, OVSSwitch
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink


from nmass_topo import NMaaSTopo

import logger as l

class NMaaSNetwork():
    def __init__(self):

        self.log = l.getLogger(self.__class__.__name__, "DEBUG")
        #fire up underlying network infrastructure
        topo = NMaaSTopo()

        #create a remote controller instance
        c = RemoteController('c0', '127.0.0.1', 6633)

        # Change the args of GenericTree() to your desired values. You could even get them from command line.
        net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, switch=OVSSwitch, controller=c)
        net.start()

        self.log.info("Add default gw to hosts")
        for h in net.hosts:
            cmd = "ip route add 0.0.0.0/0 dev {}".format(h.defaultIntf())
            self.log.debug(cmd)
            h.cmd(cmd)

        CLI(net)
        net.stop()



# if the script is run directly (sudo custom/optical.py):
if __name__ == '__main__':
    setLogLevel('info')
    nmaas = NMaaSNetwork()



