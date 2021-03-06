import os

from webob.static import DirectoryApp

import invoke as invoke
import logger as l
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event,dpset
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet,ethernet
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ether import ETH_TYPE_CFM
from ryu.ofproto.ether import ETH_TYPE_LLDP
from ryu.topology import event
from ryu.topology.api import get_switch, get_link

# Topo
# h3 -- s2 -- s1 -- h1
#      /
#     h2

from pprint import pprint
# pprint (vars(your_object))

nmaas_network_controller_instance_name = 'nmaas_network_controller_istance_name'
latency_url = '/measurement/latency-hop-by-hop/{host_from}/{host_to}'

# could be higher, I just defined a high number here
HIGHEST_PRIORITY = 1000


class NMaaS_Network_Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    mac_to_ports = dict()



    _CONTEXTS = {'wsgi': WSGIApplication}

    hosts = {
                    'h1':
                      {
                        'ip':"10.0.0.1",
                        'mac':"00:00:00:00:00:01"
                      },
                    'h2':
                        {
                            'ip': "10.0.0.2",
                            'mac': "00:00:00:00:00:02"
                        },
                    'h3':
                        {
                            'ip': "10.0.0.3",
                            'mac': "00:00:00:00:00:03"
                        },

    }

    paths = {
        "h1": {
            "h2": ["s1", "s2"],
            "h3": ["s1", "s2"]
        },
        "h2": {
            "h1": ["s2", "s1"],
            "h3": ["s2"]
        },
        "h3": {
            "h1": ["s2", "s1"],
            "h2": ["s2"]
        }
    }

    #store switch names and their datapath objects
    switches =  {
                    "s1":   {
                                'datapath': None,
                                'port_to' : {
                                                "h1": 1,
                                                "s2": 2
                                            },
                                'recent_port_data': None
                            },
                    "s2":   {
                                'datapath': None,
                                'port_to' : {
                                                "h2": 1,
                                                "h3": 2,
                                                "s1": 3
                                            },
                                'recent_port_data': None
                            }
                }
    # switch_to_dpid = {
    #     "s1": dpid_lib.str_to_dpid("0000000000000001"),
    #     "s2": dpid_lib.str_to_dpid("0000000000000002"),
    # }

    # this dictionary stores the lastly added port data for the switches
    switches_recent_ports = dict(dict())  # updated by PORT ADD and DELETE functions

    def __init__(self, *args, **kwargs):
        super(NMaaS_Network_Controller, self).__init__(*args, **kwargs)
        # get a logger
        self.log = l.getLogger(self.__class__.__name__, "DEBUG")
        self.log.info("UP and RUNNING!")

        self.log.debug("Registering NMAAS CONTROLLER RESTAPI")
        wsgi = kwargs['wsgi']
        wsgi.register(NMaaS_Network_Controller_RESTAPI,
                      {nmaas_network_controller_instance_name: self})

        # self.log.debug("Registering GUI_TOPOLOGY")
        # wsgi.register(GUIServerController,
        #               {nmaas_network_controller_instance_name: self})


        #create nmaas fw instance
        self.nmaas_fw = NMaaS_FrameWork(self)

        self.topology_api_app = self

    def send_flow_mod(self, datapath, table_id, match, inst, **args):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        table_id = table_id
        cookie = args.get('cookie', 0)
        cookie_mask = args.get('cookie_mask',0)
        idle_timeout = args.get('idle_timeout', 0)
        hard_timeout = args.get('hard_timeout', 0)
        priority = args.get('priority', 100)
        buffer_id = args.get('buffer_id', ofp.OFP_NO_BUFFER)
        mod_type = args.get('mod_type', ofp.OFPFC_ADD)

        req = ofp_parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                    table_id, mod_type,
                                    idle_timeout, hard_timeout,
                                    priority, buffer_id,
                                    ofp.OFPP_ANY, ofp.OFPG_ANY,
                                    ofp.OFPFF_SEND_FLOW_REM,
                                    match, inst)
        datapath.send_msg(req)

    def install_flow_rules(self, datapath):
        '''
        This function installs the flow flow rules regarding to the paths
        :param dp_id:
        :return:
        '''
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        #table=0 will differentiate across ARP and non-ARP packets
        #table=1 handles ARP packets - floods
        #table=100 IP-based normal packet forwarding


        # ---------------------- TABLE 0 ----------------------
        #create table=0 for the given datapath
        #ARP to table=1
        table_id=0
        match = ofp_parser.OFPMatch(eth_type=0x0806)
        inst = [ofp_parser.OFPInstructionGotoTable(1)]
        self.send_flow_mod(datapath,table_id,match,inst)

        #NON-ARP, ETH/IP -> table=100
        match = ofp_parser.OFPMatch(eth_type=0x0800)
        inst = [ofp_parser.OFPInstructionGotoTable(100)]
        self.send_flow_mod(datapath,table_id,match,inst)
        # ----------------------------------------------------

        # ----------------------- TABLE 1 ---------------------
        table_id = 1
        match = None
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        self.send_flow_mod(datapath,table_id,match,inst)
        # -----------------------------------------------------


        #specific tables for different switches
        # ----------------------- TABLE 100 -------------------
        table_id = 100
        # -----------------======== S1 ========----------------
        if datapath.id == 1:
            match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.1')
            actions = [ofp_parser.OFPActionOutput(1, 0)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            self.send_flow_mod(datapath,table_id,match,inst)

            match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.2')
            actions = [ofp_parser.OFPActionOutput(2, 0)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            self.send_flow_mod(datapath, table_id, match, inst)

            match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.3')
            actions = [ofp_parser.OFPActionOutput(2, 0)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            self.send_flow_mod(datapath, table_id, match, inst)
        # =====================================================
        elif datapath.id == 2:
            match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.2')
            actions = [ofp_parser.OFPActionOutput(1, 0)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            self.send_flow_mod(datapath, table_id, match, inst)

            match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.3')
            actions = [ofp_parser.OFPActionOutput(2, 0)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            self.send_flow_mod(datapath, table_id, match, inst)

            match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst='10.0.0.1')
            actions = [ofp_parser.OFPActionOutput(3, 0)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            self.send_flow_mod(datapath, table_id, match, inst)
        # -----------------------------------------------------

    def send_get_config_request(self, datapath):
        '''
        Send config request
        :param datapath:
        :return:
        '''
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPGetConfigRequest(datapath)
        self.log.info("Sending get-config to switch {}".format(datapath.id))
        datapath.send_msg(req)


    # ---------- TOPOLOGY DISCOVERY ----------------
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)

        switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]

        self.log.info(switches)
        self.log.info(links)
    # ----------------------------------------------

    @set_ev_cls(ofp_event.EventOFPGetConfigReply, MAIN_DISPATCHER)
    def get_config_reply_handler(self, ev):
        '''
        get config reply
        :param ev:
        :return:
        '''
        self.log.infor("get-config reply:")
        self.log.info(ev)
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        flags = []

        if msg.flags & ofp.OFPC_FRAG_NORMAL:
            flags.append('NORMAL')
        if msg.flags & ofp.OFPC_FRAG_DROP:
            flags.append('DROP')
        if msg.flags & ofp.OFPC_FRAG_REASM:
            flags.append('REASM')
        self.log.info('OFPGetConfigReply received: '
                          'flags=%s miss_send_len=%d',
                          ','.join(flags), msg.miss_send_len)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        '''
        Switch sends back a reply to the feaure request messages
        :param ev:
        :return:
        '''
        msg = ev.msg

        self.log.info('OFPSwitchFeatures received: '
                          'datapath_id=0x%016x n_buffers=%d '
                          'n_tables=%d auxiliary_id=%d '
                          'capabilities=0x%08x',
                          msg.datapath_id, msg.n_buffers, msg.n_tables,
                          msg.auxiliary_id, msg.capabilities)

    # ------------ SWITCH CONNECTED ----------
    # @set_ev_cls(dpset.EventDP, CONFIG_DISPATCHER)
    # def connection_handler(self, ev):
    #     # pself.log.info(vars(ev))
    #     enter_leave = ev.enter
    #     dp = ev.dp
    #
    #     #update switches dictionary
    #     self.switches["s{}".format(dp.id)]['datapath']=dp
    #
    #     ports = ev.ports
    #     # self.log.info("Enterr_leave: {}".format(enter_leave))
    #     if enter_leave == True:
    #         self.log.info("Switch with datapath id {} has been connected".format(dp.id))
    #         self.install_flow_rules(dp)
    #         if dp.id not in self.mac_to_ports:
    #             self.mac_to_ports[dp.id] = dict()
    #     else:
    #         self.log.info("Switch with datapath id {} has been disconnected".format(dp.id))
    #         if dp.id in self.mac_to_ports:
    #             self.mac_to_ports.pop(dp.id)
    #
    #     self.log.info("mac_to_ports:{}".format(self.mac_to_ports))

    # ------------ PORT ADD ------------
    @set_ev_cls(dpset.EventPortAdd, CONFIG_DISPATCHER)
    def port_add_handler(self, ev):
        dp = ev.dp
        port = ev.port
        self.log.info("New port has been added to switch {}".format(dp.id))
        self.log.info("\tno:\t{}".format(port.port_no))
        self.log.info("\tname:\t{}".format(port.name))
        self.log.info("\tMAC:\t{}".format(port.hw_addr))
        self.log.info("\tstate:\t{}".format(port.state))

        # update latest port data
        self.switches["s{}".format(dp.id)]["recent_port_data"]=  {
                                                                    "port_no":port.port_no,
                                                                    "port_name:": port.name,
                                                                    "port_hw_addr":port.hw_addr,
                                                                    "port_state": port.state
                                                                 }

    # ------------ PORT DELETE ------------
    @set_ev_cls(dpset.EventPortDelete, CONFIG_DISPATCHER)
    def port_del_handler(self, ev):
        dp = ev.dp
        port = ev.port
        self.log.info("New port has been deleted to switch {}".format(dp.id))
        self.log.info("\tno:\t{}".format(port.port_no))
        self.log.info("\tname:\t{}".format(port.name))
        self.log.info("\tMAC:\t{}".format(port.hw_addr))
        self.log.info("\tstate:\t{}".format(port.state))

    # ------------ PORT MODIFY ------------
    @set_ev_cls(dpset.EventPortModify, CONFIG_DISPATCHER)
    def port_mod_handler(self, ev):
        dp = ev.dp
        port = ev.port
        self.log.info("A port has been modified on switch {}".format(dp.id))
        self.log.info("\tno:\t{}".format(port.port_no))
        self.log.info("\tname:\t{}".format(port.name))
        self.log.info("\tMAC:\t{}".format(port.hw_addr))
        self.log.info("\tstate:\t{}".format(port.state))

    @set_ev_cls(ofp_event.EventOFPGetConfigReply, MAIN_DISPATCHER)
    def get_config_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.flags == ofp.OFPC_FRAG_NORMAL:
            flags = 'NORMAL'
        elif msg.flags == ofp.OFPC_FRAG_DROP:
            flags = 'DROP'
        elif msg.flags == ofp.OFPC_FRAG_REASM:
            flags = 'REASM'
        elif msg.flags == ofp.OFPC_FRAG_MASK:
            flags = 'MASK'
        else:
            flags = 'unknown'
        self.log.debug('OFPGetConfigReply received: '
                          'flags=%s miss_send_len=%d',
                          flags, msg.miss_send_len)

    # ------------ PACKET_IN ------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        vlan = False
        arp = False
        icmp = False
        lldp = False

        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        print eth
        #ignore lldp
        if eth.ethertype in (ETH_TYPE_LLDP, ETH_TYPE_CFM):
            # self.log.info("LLDP packet - ignore")
            self.get_topology_data(ev)
            return
        # if eth.ethertype in (ETH_TYPE_LLDP, ETH_TYPE_CFM):
        #     return

        dp = msg.datapath

        # pkt = packet.Packet(ev.msg.data)
        # lldp_packet = packet.Packet(msg.data).get_protocol(packet.ethernet.lldp)
        # print lldp_packet

        # for p in pkt.protocols:
        #     print p.protocol_name
        # self.log.info("\nPacket_IN")

        # self.log.info("...from DpId:\t{}".format(dp.id))
        # self.get_topology_data(ev)

class NMaaS_FrameWork():
    '''
    This class is devoted to do system level calls, e.g., instantiating new hosts, connecting them to switches, etc.
    '''
    PING_ID = 200 # this will represent the PING MODULE in the IP ADDRESS' second segment
    OTHER_MODULE_ID = 100 #
    def __init__(self, nmaas_network_controller):
        '''
        Constructor
        :param nmaas_network_controller: reference to main NMaaS_Network_Controller to reach its functions, e.g., flowmod
        '''
        # get a logger
        self.log = l.getLogger(self.__class__.__name__, "DEBUG")
        self.log.info("Instantiated for system level commands...")
        # self.log.info("NMaaS Framework instantiated for system level commands...")
        self.nmaas_network_controller = nmaas_network_controller


        self.modules = {"latency-hbh":dict()}

        #this dictionary stores data relevant to switches, e.g., used veths, ips
        self.switch_data = dict()

    def _register_latency_request(self, from_to):
        # hbh = {from_to: dict()}
        if from_to not in self.modules["latency-hbh"]:
            self.modules["latency-hbh"][from_to]={
                                                    "namespaces":list(),
                                                    "switches":dict()
                                                }


    def _delete_latency_request(self,from_to):
        self.log.debug(self.modules)
        self.log.info("Deleting latency modules' data...")
        key = from_to
        if key in self.modules["latency-hbh"]:
            #removing namespaces
            for ns in self.modules["latency-hbh"][key]["namespaces"]:
                invoke.invoke(command="ip netns delete {}".format(ns))
            #giving back the used veth ids and ip_ends
            for sw in self.modules["latency-hbh"][key]["switches"]:
                i=0
                for veth in self.modules["latency-hbh"][key]["switches"][sw]['used_veths']:
                    #give these elements back to self.switch_data dictionary's VETHS
                    # self.log.error(self.switch_data[sw])
                    self.switch_data[sw]["veth_id"].append(veth)

                    #delete ports from switch (only the first one is connected to the switch
                    if i == 0:
                        cmd="ovs-vsctl del-port {} {}-ping-veth{}".format(sw,sw,veth)
                        invoke.invoke(command=cmd)

                    i=i+1

                #sort self.switch_data again as it was in the beginning
                self.switch_data[sw]['veth_id'].sort(reverse=True)

                #give these elements back to the self.switch_data dictionary's IPs
                ip=self.modules["latency-hbh"][key]["switches"][sw]['used_ip']
                #according to the last IP id, we remove the corresponding flow rules
                self.delete_flow_rule(switch=sw,module_id="ping",module_ip_end=ip)
                # give these elements back to self.switch_data dictionary
                self.switch_data[sw]["ip_end"].append(ip)
                #sort self.switch_data again as it was in the beginning
                self.switch_data[sw]['ip_end'].sort(reverse=True)

            del self.modules["latency-hbh"][key]
        self.log.info("[DONE]")
        self.log.debug(self.modules)



    def add_nmaas_module(self, **kwargs):
        '''
        This function creates a network namespace on the given switch, and configures the ip addresses, gateways accordingly.
        Furthermore, it connects the namespace to the switch with veth-pairs
        :param kwargs:  module - String: name of the module, e.g., ping
                        switch - String: name of the switch to connect the module, e.g., s1
                        chain_prev - String: the name of the node residing on the path before this switch, e.g., h1, s2
                        chain_next - String: the name of the node residing on the path next to this switch, e.g., h3, s2
                        from_to - String: {host_from}-{host_to} - used for identifying which namespace belongs to which measurement
        :return: the new port_no created by connecting one end of the veth pair to the switch -> it is important for latter
        rule installation
        '''



        module = kwargs.get('module', 'ping')
        switch_to_connect = kwargs.get('switch', None)
        #these are for the private function add_flow_rules(), not really used in this function
        chain_prev = kwargs.get('chain_prev', None)
        chain_next = kwargs.get('chain_next', None)
        from_to = kwargs.get('from_to', None)

        #register module
        self._register_latency_request(from_to)

        if module == "ping":
            ip_identifier = self.PING_ID
        else:
            self.log.info("Module named as {} is not supported!".format(module))
            exit(-1)

        #third segment of the module's IP address will also represent the switch id
        # get Datapath object from nmaas_controller
        datapath = self.nmaas_network_controller.switches[switch_to_connect]['datapath']
        sw_dpid = datapath.id # this will give back an integer DpID
        if sw_dpid > 255:
            self.log.info("ERROR: Switch DPID could not be greater than 255! EXITING!")
            exit(-1)

        ip = "10.{}.{}".format(ip_identifier,sw_dpid)

        #check whether the given switch was already took part in any of
        if switch_to_connect not in self.switch_data.keys():
            self.switch_data[switch_to_connect]={
                                                    "veth_id" : list(), # these lists will grow with time
                                                    "ip_end"  : list()
                                                }

        # --------- Allocating new veths -----------
        #create unused IDs for veths and unused numbers IPs' 4th segment
        if not self.switch_data[switch_to_connect]["veth_id"]:
            # TODO: what if emptyness is caused by consuming all resources ???
            #fill up with the possible numbers to create a pool (now only 127 pair of veths are possible)
            for i in range(1,255):
                self.switch_data[switch_to_connect]["veth_id"].append(i)

            #reverse list
            self.switch_data[switch_to_connect]["veth_id"].sort(reverse=True)


        #switch is already using veths, we need to increase their numbers to create fresh ones
        veths = [
                    self.switch_data[switch_to_connect]["veth_id"].pop(),
                    self.switch_data[switch_to_connect]["veth_id"].pop()
                     ]

        # --------- Allocating new IPs for veths ----------- SAME AS FOR VETHS
        # create unused IDs for veths and unused numbers IPs' 4th segment
        if not self.switch_data[switch_to_connect]["ip_end"]:
            # TODO: what if emptyness is caused by consuming all resources ???
            # fill up with the possible numbers to create a pool (now only 127 pair of veths are possible)
            for i in range(1, 255):
                self.switch_data[switch_to_connect]["ip_end"].append(i)

            # reverse list
            self.switch_data[switch_to_connect]["ip_end"].sort(reverse=True)


            # switch is already using veths, we need to increase their numbers to create fresh ones
        module_ip_end = self.switch_data[switch_to_connect]["ip_end"].pop()

        #NOW, we have self.veths 2-element-long list with the usable veth IDs
        # and the same applies for self.ip_ends

        if switch_to_connect is None:
            self.log.info("ERROR: Switch is not set")
            return

        self.log.info("Add ping module to switch {}\n".format(switch_to_connect))

        #create namespace
        ns_name = "{}-ping-{}".format(switch_to_connect,from_to)
        self.log.info("-- CREATE NAMESPACE")
        cmd = "ip netns add {}".format(ns_name)
        self.log.info(cmd)
        self.log.info(invoke.invoke(command=cmd)[0])


        #create veth pair
        self.log.info("-- CREATE VETH PAIR")
        cmd = "ip link add {}-ping-veth{} type veth peer name {}-ping-veth{}".format(switch_to_connect,
                                                                                     veths[0],
                                                                                     switch_to_connect,
                                                                                     veths[1])
        self.log.info(cmd)
        self.log.info(invoke.invoke(command=cmd)[0])

        # add secondary veth device into the namespace
        self.log.info("-- ADDING VETH PEER INTO THE NAMESPACE")
        cmd = "ip link set {}-ping-veth{} netns {}".format(switch_to_connect, veths[1], ns_name)
        self.log.info(cmd)
        self.log.info(invoke.invoke(command=cmd)[0])


        # WE DON'T NEED TO ADD IP ADDRESS TO OTHER END OF THE VETH AS IT IS CONNECTED TO OVS!
        # add ip addresses to veth devices
        # self.log.info("-- SETTING UP IP ADDRESSES FOR VETHS")
        # cmd = "ip addr add {}.{}/16 dev {}-ping-veth{}".format(ip, self.ips[0], switch_to_connect, self.veths[0])
        # self.log.info(cmd)
        # self.log.info(invoke.invoke(command=cmd)[0])

        cmd = "ip netns exec {} ip addr add {}.{}/32 dev {}-ping-veth{}".format(ns_name,
                                                                                 ip,
                                                                                 module_ip_end,
                                                                                 switch_to_connect,
                                                                                 veths[1])
        self.log.info(cmd)
        self.log.info(invoke.invoke(command=cmd)[0])

        # bring up veth devices
        self.log.info("-- BRINGING UP VETH DEVICES")
        cmd = "ip link set dev {}-ping-veth{} up".format(switch_to_connect, veths[0])
        self.log.info(cmd)
        self.log.info(invoke.invoke(command=cmd)[0])

        cmd = "ip netns exec {} ip link set dev {}-ping-veth{} up".format(ns_name,
                                                                           switch_to_connect,
                                                                           veths[1])
        self.log.info(cmd)
        self.log.info(invoke.invoke(command=cmd)[0])





        # add default gateway to veth in the namespace
        self.log.info("-- ADD DEFAULT GW TO NAMESPACE")
        cmd = "ip netns exec {} ip route add 0.0.0.0/0 dev {}-ping-veth{}".format(ns_name,
                                                                                       switch_to_connect,
                                                                                       veths[1])
        self.log.info(cmd)
        self.log.info(invoke.invoke(command=cmd)[0])

        # add veth to switch
        self.log.info("-- ADD VETH TO SWITCH")
        cmd = "ovs-vsctl add-port {} {}-ping-veth{}".format(switch_to_connect, switch_to_connect, veths[0])
        self.log.info(cmd)
        self.log.info(invoke.invoke(command=cmd)[0])

        # # this command above will initiate a PORT ADDED event to the controller, from where we could become aware
        # # of the new port number that needs to be used in the new flow rules
        # port_number = self.nmaas_network_controller.switches[switch_to_connect]['recent_ports_data']["port_no"]
        # self.log.info("new port number on switch {} is {}".format(switch_to_connect, port_number))
        #
        # return port_number

        #registering module data
        self.modules["latency-hbh"][from_to]["namespaces"].extend([ns_name])
        self.modules["latency-hbh"][from_to]["switches"][switch_to_connect]={
                                                                                "used_veths":list(veths),#kinda copy veths
                                                                                "used_ip":module_ip_end

                                                                             }
        #Adding flow rules
        self._add_flow_rules(switch=switch_to_connect,
                             chain_prev=chain_prev,
                             chain_next=chain_next,
                             module_id=ip_identifier, # second segment of the IP address of the module, e.g., 200 (PING)
                             module_ip_end=module_ip_end # last segment of trhe IP address identifying exactly the module
                             )




    def _add_flow_rules(self, **kwargs):
        '''
        This function will add the flow rules into the given switch
        :param kwargs:  module_id - Int: IP identifier of the module (shown in the second segment of the IP addresses)
                        module_ip_end - Int: IP identifier of the practical module (shown in the fourth segment of the IP addresseS)
                        switch- String: name of the switch, e.g., s1
                        chain_prev - String: the name of the node residing on the path before this switch, e.g., h1, s2
                        chain_next - String: the name of the node residing on the path next to this switch, e.g., h3, s2
        :return:
        '''
        switch = kwargs.get('switch', None)
        module_id = kwargs.get('module_id', 'ping')
        module_ip_end = kwargs.get('module_ip_end', 1)
        chain_prev = kwargs.get('chain_prev', None)
        chain_next = kwargs.get('chain_next', None)


        # third segment of the module's IP address will also represent the switch id
        # get Datapath object from nmaas_controller
        datapath = self.nmaas_network_controller.switches[switch]['datapath']



        #add flow rules according to the known ports
        #if the destination IP is in the range of newly created range, we need to direct traffic to the next switch if
        #the traffic came in through the freshly made port. Otherwise, the traffic should be sent to the ping module
        #through the freshly made port
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser


        # ==========>>>>>>> TO THE PING MODULE
        # we need /16 range match here to send out each packet coming from the PING module to other switches
        ip=("10.{}.{}.{}".format(module_id,datapath.id, module_ip_end), '255.255.255.255')
        #traffic from the PING module to other PING modules, i.e., to the direction of other switches
        match = ofp_parser.OFPMatch(eth_type=0x0800,  ipv4_dst=ip)
        actions = [ofp_parser.OFPActionOutput(self.nmaas_network_controller.switches[switch]['recent_port_data']['port_no'], 0)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        self.nmaas_network_controller.send_flow_mod(
            datapath,  # DP
            0,         # table_id
            match,     # match
            inst,      # instruction
            priority=HIGHEST_PRIORITY  #additional arguments
        )

        if chain_prev is not None:
            # prev. node is a switch, then we need a flow rule for that and in order to reach this, we need the port no
            # to that switch
            output_port_to_prev_switch = self.nmaas_network_controller.switches[switch]['port_to'][chain_prev]
            ip_range = ("10.{}.{}.0".format(module_id, self.nmaas_network_controller.switches[chain_prev]['datapath'].id), '255.255.255.0')
            # add flow rules that directs traffic to the PING modules
            match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip_range)
            actions = [ofp_parser.OFPActionOutput(output_port_to_prev_switch, 0)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            self.nmaas_network_controller.send_flow_mod(
                datapath,  # DP
                0,  # table_id
                match,  # match
                inst,  # instruction
                priority=HIGHEST_PRIORITY  # additional arguments
            )
        else:
            self.log.info("There is no prev node!")
            self.log.info(" ---- BEGINNING OF CHAIN ----")

        # ==========>>>>>>> FROM THE PING MODULE TO CHAIN NEXT
        if chain_next is not None:
            #next node is a switch, then we need a flow rule for that and in order to reach this, we need the port no
            #to that switch
            output_port_to_next_switch = self.nmaas_network_controller.switches[switch]['port_to'][chain_next]

            ip_range = ("10.{}.{}.0".format(module_id, self.nmaas_network_controller.switches[chain_next]['datapath'].id), '255.255.255.0')
            # add flow rules that directs traffic to the PING modules
            match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip_range)
            actions = [ofp_parser.OFPActionOutput(output_port_to_next_switch, 0)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            self.nmaas_network_controller.send_flow_mod(
                datapath,  # DP
                0,  # table_id
                match,  # match
                inst,  # instruction
                priority=HIGHEST_PRIORITY  # additional arguments
            )
        else:
            self.log.info("There is no next node!")
            self.log.info(" ---- END OF CHAIN ----")


    def _analyze_ping_files(self, filename):
        '''
        This private function reads the ping results files, analyzes is, and calculates the average RTT
        :param filename: String - the filename storing the ping's output
        :return: average RTT
        '''
        # from host to the first hop
        get_ping_data_cmd = "cat {}|tail -n 3|cut -d '%' -f 2".format(filename)
        # this command read the last 3 line of the 4 ping, cuts the relevant time=X data, cuts out time=
        ping_data = invoke.invoke(command=get_ping_data_cmd)[0].split("\n")[:-1]
        # invoke returns a list, where the first (0th) element is the stdout, which stores escaped "\n" chars.
        #   for instance: '56.8 ms\n151 ms\n135 ms\n'
        # splitting it according to this char generates a 4-element-long list having an empty '' element at the end
        #   for instance: ['56.8 ms', '151 ms', '135 ms', '']
        # to get rid of that last element, we use [:-1]
        #   for instance ['56.8 ms', '151 ms', '135 ms']
        # self.log.info(ping_data)

        avg = 0
        unit = ping_data[0].split(' ')[1]
        for i in ping_data:
            ping = i.split(' ')
            avg+=float(ping[0]) # this will cut down the unit ('ms')
            if unit != ping[1]:
                self.log.info("Something is really wrong! Not all pings have the same unit")
                #TODO: handle this case

        #delete ping files!
        # self.log.info("Deleting ping logs")
        invoke.invoke(command="rm -rf {}".format(filename))

        # return the average RTT value
        return avg/3.0


    def delete_flow_rule(self, **kwargs):
        '''
        This function removes flows from the switches
        :param kwargs:
        :return:
        '''


        switch = kwargs.get('switch', None)
        module_id = kwargs.get('module_id', 'ping')
        module_ip_end = kwargs.get('module_ip_end', None)
        self.log.info("Deleting {}-module related flow rule(s) from switch {}".format(module_id,switch))

        if module_id.upper() == "PING":
            module_id = self.PING_ID


        # third segment of the module's IP address will also represent the switch id
        # get Datapath object from nmaas_controller
        datapath = self.nmaas_network_controller.switches[switch]['datapath']

        # add flow rules according to the known ports
        # if the destination IP is in the range of newly created range, we need to direct traffic to the next switch if
        # the traffic came in through the freshly made port. Otherwise, the traffic should be sent to the ping module
        # through the freshly made port
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        # ==========>>>>>>> TO THE PING MODULE
        # we need /16 range match here to send out each packet coming from the PING module to other switches
        ip = ("10.{}.{}.{}".format(module_id, datapath.id, module_ip_end), '255.255.255.255')
        # traffic from the PING module to other PING modules, i.e., to the direction of other switches
        match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip)
        actions = [
            ofp_parser.OFPActionOutput(self.nmaas_network_controller.switches[switch]['recent_port_data']['port_no'],
                                       0)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        self.nmaas_network_controller.send_flow_mod(
            datapath,  # DP
            0,  # table_id
            match,  # match
            inst,  # instruction
            priority=HIGHEST_PRIORITY,  # additional arguments
            mod_type=ofp.OFPFC_DELETE # removing flow
        )




    def do_ping(self, **kwargs):
        '''
        This function will do the practical pinging
        :param kwargs:  switch - String: The switch the ping module is running
                        chain_prev - String: The previous node in the chain that needs to be pinged if it is a host
                        chain_next - String: The next node in the chain that needs to be pinged
                        from_to - String: {host_from}-{host_to} - used for identifying which namespace belongs to which measurement
        :return: hop_by_hop_latency: a datastructure representing the the results
        '''
        switch = kwargs.get('switch', None)
        chain_prev = kwargs.get('chain_prev', None)
        chain_next = kwargs.get('chain_next', None)
        from_to = kwargs.get('from_to', None)


        ns_name = "{}-ping-{}".format(switch,from_to)

        #this will indicate whether a certain call of this function pings 2 (host and ping module), or just one (chain_next)
        first_hop_ping = True

        #this will be the return value - it is a list, since in the first iteration two pings need to be done
        #it is always zeroed each time this function is called, however from the caller side we keep track of all
        #latency data by extending there a list with this return_list in each step
        return_list = list()

        #this will be the end of the command grepping the relevant part, and seding the string 'time=' to a special
        #character '%', which never appears in pings output. This would make it easier to tokenize the output during
        #analyzation
        grep_and_sed = "grep '64\ bytes'|sed 's/time\=/%/'"

        #first case, when chain_prev is a host -> this time we need to ping that, as we don't want it to ping us
        if chain_prev.startswith("h"):
            self.log.info("Measuring latency between {} - {}".format(chain_prev, switch))

            output_file = "ping_from_{}_to_{}".format(switch,chain_prev)
            ping_cmd = "ip netns exec {} ping -c 4 {} |{} >> {}".format(
                                                                ns_name,
                                                                self.nmaas_network_controller.hosts[chain_prev]["ip"],
                                                                grep_and_sed,
                                                                output_file)
            invoke.invoke(command=ping_cmd)
            #store results in the return_list
            return_list.extend([self._analyze_ping_files(output_file)])

        else:
            first_hop_ping = False

        self.log.info("Measuring latency between {} - {}".format(switch, chain_next))

        output_file = "ping_from_{}_to_{}".format(switch, chain_next)
        if chain_next.startswith("s"):

            #a ping module needs to be ping
            #First, we need to figure out the exact IP address of that module
            ip="10.{}.{}.{}".format(
                                    self.PING_ID, # this will be 200
                                    self.nmaas_network_controller.switches[chain_next]["datapath"].id,  #this will be
                                                                                                        # and integer

                                    self.switch_data[chain_next]["ip_end"][-1]-1    #there is a pool for the IPs and
                                                                                    #Veths for a given switch and we
                                                                                    #always take the last one out when
                                                                                    #instantiating new module, so the
                                                                                    #last unused-1 will be the last used
                                    )

            ping_cmd = "ip netns exec {} ping -c 4 {} |{} >> {}".format(ns_name,
                                                                        ip,
                                                                        grep_and_sed,
                                                                        output_file)

        else:

            # chain_next is a hop and, on the other hand, we reached the end of the chain
            ping_cmd = "ip netns exec {} ping -c 4 {} |{} >> {}".format(ns_name,
                                                                        self.nmaas_network_controller.hosts[chain_next]["ip"],
                                                                        grep_and_sed,
                                                                        output_file)


        invoke.invoke(command=ping_cmd)

        # store results in the return_list
        return_list.extend([self._analyze_ping_files(output_file)])


        return return_list

    def delete_nmaas_module(self, **kwargs):
        '''
        This function creates a network namespace on the given switch, and configures the ip addresses, gateways accordingly.
        Furthermore, it connects the namespace to the switch with veth-pairs
        :param kwargs:  module - String: name of the module, e.g., ping
                        from_to - String: {host_from}-{host_to} - used for identifying which namespace belongs to which measurement
        '''
        module = kwargs.get('module', None)
        from_to = kwargs.get('from_to', None)


        if module.upper() == "PING":
            self._delete_latency_request(from_to)


# ----------- ============= REST API FOR TENANT-CONTROLLER COMMUNICATION ============== -------------
PATH = os.path.dirname(__file__)

class NMaaS_Network_Controller_RESTAPI(ControllerBase):
    '''
    This class is devoted to describe a REST API for tenant-controller communications
    '''

    def __init__(self, req, link, data, **config):
        super(NMaaS_Network_Controller_RESTAPI, self).__init__(req, link, data, **config)
        self.nmaas_network_controller_app = data[nmaas_network_controller_instance_name]

        path = "%s/html/" % PATH
        print path
        self.static_app = DirectoryApp(path)

    @route('hop-by-hop-latency', latency_url, methods=['GET'] )
    def calculate_latency(self, req, **kwargs):
        nmaas = self.nmaas_network_controller_app

        # parsing GET to get {host_from} and {host_to}
        host_from = kwargs.get('host_from',"h1")
        host_to = kwargs.get('host_to', "h3")

        #check whether host exists
        if host_from not in nmaas.paths.keys():
            return "\nUnknown host {}\n".format(host_from)
        elif host_to not in nmaas.paths.keys():
            return "\nUnkown host {}\n".format(host_to)
        else:

            #registering request
            latencies = list()

            print("\nCalculating hop-by-hop latency between {} and {}\n".format(host_from,host_to))
            print("The path is:\n")
            print host_from,
            for sw in nmaas.paths[host_from][host_to]:
                #here only switches are coming
                print "-> "+sw,
            print "-> " + host_to

            hop_count = len(nmaas.paths[host_from][host_to]) - 1
            path = nmaas.paths[host_from][host_to]
            for i,sw in enumerate(path):
                #here only switches are coming
                if i == 0:
                    #beginning of the chain
                    chain_prev = None
                else:
                    chain_prev = path[i-1]
                if i == hop_count:
                    #end of the chain
                    chain_next = None
                else:
                    chain_next = path[i+1]
                nmaas.nmaas_fw.add_nmaas_module(module='ping',
                                                switch=path[i],
                                                chain_prev=chain_prev,
                                                chain_next=chain_next,
                                                from_to="{}-{}".format(host_from, host_to))

            # namespaces and forwarding rules are installed -> Let's do the pings
            print("Hop-by-hop measurement is ON!")
            hop_count = len(nmaas.paths[host_from][host_to]) - 1
            print("It will take approx. {} seconds".format((hop_count+1)*4))

            path = nmaas.paths[host_from][host_to]
            for i, sw in enumerate(path):
                # here only switches are coming
                if i == 0:
                    # beginning of the chain
                    chain_prev = host_from
                else:
                    chain_prev = path[i - 1]
                if i == hop_count:
                    # end of the chain
                    chain_next = host_to
                else:
                    chain_next = path[i + 1]
                latencies.extend(nmaas.nmaas_fw.do_ping(switch=path[i],
                                                        chain_prev=chain_prev,
                                                        chain_next=chain_next,
                                                        from_to="{}-{}".format(host_from, host_to)))

            ret_val = "Latency data from {} to {}\n".format(host_from, host_to)
            print(ret_val)
            for i,latency in enumerate(latencies):
                hop_latency = "{} hop: {}".format(i+1,latency)
                print(hop_latency)
                ret_val += hop_latency +"\n"


            print(nmaas.nmaas_fw.delete_nmaas_module(module="ping", from_to="{}-{}".format(host_from, host_to)))
            #removing request
            # nmaas.nmaas_fw.delete_latency_request(host_from,host_to)
            return  ret_val

    @route('topology', '/{filename:.*}')
    def static_handler(self, req, **kwargs):
        if kwargs['filename']:
            req.path_info = kwargs['filename']
        return self.static_app(req)



app_manager.require_app('ryu.app.rest_topology')
app_manager.require_app('ryu.app.ws_topology')
app_manager.require_app('ryu.app.ofctl_rest')



#