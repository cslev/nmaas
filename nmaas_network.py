
from mininet.node import CPULimitedHost, Host, OVSSwitch
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink


from nmaas_topo import NMaaSTopo

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

        # we are 'playing' with non-STP topologies, i.e., there are rings in the topology, so ARP broadcast storm
        # would arise. If we enable ARP, then it blocks the links, i.e., by blocking some ports, multiple paths will
        # disappear
        # Thus, we set here the ARP tables manually for all hosts; TODO: make it more automatic later in the controller

        number_of_hosts = len(net.hosts)
        for i,h in enumerate(net.hosts):
            # print net.hosts[0].params['ip']
            # print i,h
            if i < (number_of_hosts-1):
                cmd = "ping -c1 {}".format(net.hosts[i+1].params['ip'])
                # print cmd
                h.cmd(cmd)
            else:
                cmd = "ping -c1 {}".format(net.hosts[0].params['ip'])
                # print cmd
                h.cmd(cmd)

        #     for i in range(1,number_of_hosts):
        #         if ("%02d" %i) == h.mac.split(':')[5]:
        #             continue
        #         h.cmd("arp -s 10.0.0.{} 00:00:00:00:00:")

        self.log.info("Add default gw to hosts")
        # for h in net.hosts:
        #     cmd = "ip route add 0.0.0.0/0 dev {}".format(h.defaultIntf())
        #     self.log.debug(cmd)
        #     h.cmd(cmd)

        # for s in net.switches:
        #     cmd = "ovs-vsctl set bridge {} stp-enable=true".format(s)
        #     print("Enabling STP on {}".format(s))
        #     s.cmd(cmd)
        # net.switches[1].cmd(cmd)

        CLI(net)
        net.stop()



# if the script is run directly (sudo custom/optical.py):
if __name__ == '__main__':
    setLogLevel('info')
    nmaas = NMaaSNetwork()



