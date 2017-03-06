# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Usage example

1. Join switches (use your favorite method):
$ sudo mn --controller remote --topo tree,depth=3

2. Run this application:
$ PYTHONPATH=. ./bin/ryu run \
    --observe-links ryu/app/gui_topology/nmaas_network_controller.py

3. Access http://<ip address of ryu host>:8080 with your web browser.

@route('topology', '/{filename:(?!v1.0).*}')
    @route('topology', '/app/{filename:.*}')
"""

import os

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ether import ETH_TYPE_CFM
from ryu.ofproto.ether import ETH_TYPE_LLDP
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link, get_host
from ryu.controller import ofp_event,dpset
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet,ethernet
from ryu.app.wsgi import  WSGIApplication
from ryu.base import app_manager

# from nmaas_network_controller_bak import NMaaS_FrameWork
from nmaas_framework import NMaaS_FrameWork
from nmaas_rest_api import NMaaS_RESTAPI
from nmaas_network_graph import NMaaS_Network_Graph

import invoke as invoke
import logger as l


from pprint import pprint
# pprint (vars(your_object))

nmaas_network_controller_instance_name = 'nmaas_network_controller_instance_name'

# Serving static files
class NMaaS_Network_Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'wsgi': WSGIApplication,
    }

    # hosts = {
    #     'h1':
    #         {
    #             'ip': "10.0.0.1",
    #             'mac': "00:00:00:00:00:01"
    #         },
    #     'h2':
    #         {
    #             'ip': "10.0.0.2",
    #             'mac': "00:00:00:00:00:02"
    #         },
    #     'h3':
    #         {
    #             'ip': "10.0.0.3",
    #             'mac': "00:00:00:00:00:03"
    #         },
    #
    # }
    #
    # paths = {
    #     "h1": {
    #         "h2": ["s1", "s2"],
    #         "h3": ["s1", "s2"]
    #     },
    #     "h2": {
    #         "h1": ["s2", "s1"],
    #         "h3": ["s2"]
    #     },
    #     "h3": {
    #         "h1": ["s2", "s1"],
    #         "h2": ["s2"]
    #     }
    # }
    #
    # # store switch names and their datapath objects
    # switches = {
    #     "s1": {
    #         'datapath': None,
    #         'port_to': {
    #             "h1": 1,
    #             "s2": 2
    #         },
    #         'recent_port_data': None
    #     },
    #     "s2": {
    #         'datapath': None,
    #         'port_to': {
    #             "h2": 1,
    #             "h3": 2,
    #             "s1": 3
    #         },
    #         'recent_port_data': None
    #     }
    # }
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

        self.log.debug("Registering GUI TOPOLOGY RESTAPI")
        wsgi = kwargs['wsgi']
        wsgi.register(NMaaS_RESTAPI,
                      {nmaas_network_controller_instance_name: self})

        #create nmaas fw instance
        self.nmaas_fw = NMaaS_FrameWork(self)

        #create nmass_network_graph instance
        self.nmaas_graph = NMaaS_Network_Graph()

        self.topology_api_app = self

        #learning switch
        self.mac_to_ports = dict()

        #nodes
        self.switches = dict()
        self.hosts = dict()

        self.paths = dict()


    def send_flow_mod(self, datapath, table_id, match, inst, **args):
        '''
        Sending a flow_mod to the given switch
        :param datapath: Datapath - datapath of the switch
        :param table_id: Int - number of the table
        :param match: Match - the match object
        :param inst: Inst - the instruction object implying the actions
        :param args: cookie=0, cookie_mask=0,idle_timeout=0,hard_timeout=0,priority=100,buffer_id=OFP_NO_BUFFER,
                    mod_type= OFPFC_ADD
        :return: nothing
        '''
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

    def install_initial_flow_rules(self, datapath):
        '''
        This function installs initial ARP related flow rules in the switch
        :param datapath: the datapath object, i.e., the switch
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

    # ------------ SWITCH CONNECTED ----------
    @set_ev_cls(dpset.EventDP, CONFIG_DISPATCHER)
    def connection_handler(self, ev):
        # pself.log.info(vars(ev))
        enter_leave = ev.enter
        dp = ev.dp

        ports = ev.ports
        # self.log.info("Enterr_leave: {}".format(enter_leave))
        if enter_leave == True:
            self.log.info("Switch with datapath id {} has been connected".format(dp.id))
            # self.install_initial_flow_rules(dp)
            self.switches[dp.id]=dp
            if dp.id not in self.mac_to_ports:
                self.mac_to_ports[dp.id] = dict()

            #update topology
            self.update_topology_data()

        else:
            self.log.info("Switch with datapath id {} has been disconnected".format(dp.id))
            if dp.id in self.switches:
                self.switches.pop(dp.id)
            if dp.id in self.mac_to_ports:
                self.mac_to_ports.pop(dp.id)


            # update topology
            self.update_topology_data()




    # ---------- TOPOLOGY UPDATE ----------------
    def update_topology_data(self):
        '''
        This function updates the topology related to hosts and links among switches.
        Switches are in the topology and their statuses are handled in connection up/down event in function connection_handler()
        :return:
        '''
        self.log.info("Updating topology...")
        #FIRST ADD EVERYTHING TO THE NETWORK (DUPLICATES ARE HANDLED BY DEFAULT)
        #get switch list
        switch_list = list()
        self.log.info("SWITCH LIST BEFORE UPDATE: {}".format(switch_list))
        switch_list = get_switch(self.topology_api_app, None)
        self.log.info("SWITCH LIST AFTER UPDATE: {}".format(switch_list))

        #temprary lists for switches and hosts
        s_list = list()
        h_list = list()

        # update switches in topology
        for switch in switch_list:
            switch_name = "s-{}".format(switch.dp.id)
            #add switch to the temporary list of switches
            s_list.append(switch_name)
            #add switchs to graph
            self.nmaas_graph.add_node(switch_name, dp=switch.dp, port=switch.ports)

        # get links and their endpoints
        links_list = get_link(self.topology_api_app, None)

        #this only goes through the switch links
        for link in links_list:
            print link
            # print "s-{}".format(link.src.dpid), "s-{}".format(link.dst.dpid), \
            #                     "src_port = {}".format(link.src.port_no), \
            #                     "dst_port = {}".format(link.dst.port_no)
            #networkx links in Graph() are not differentiated by source and destination, so a link and its data become
            #updated when add_edge is called with the source and destination swapped
            if self.nmaas_graph.get_graph().has_edge("s-{}".format(link.src.dpid), "s-{}".format(link.dst.dpid)):
                #once a link is added, we do not readd it, since it just updates the data, but there won'be any new link
                print("Link {}-{} already added...skipping".format(link.src.dpid,link.dst.dpid))
                continue
            self.nmaas_graph.add_edge("s-{}".format(link.src.dpid), "s-{}".format(link.dst.dpid),
                                      src_dpid = link.src.dpid, src_port = link.src.port_no,
                                      dst_dpid=link.dst.dpid, dst_port = link.dst.port_no)

        # get hosts if there is any
        host_list = get_host(self.topology_api_app, None)
        if host_list:
            for host in host_list:
                # we create something like h-1, h-2, etc.
                host_name = "h-{}".format(host.ipv4[0].split(".")[3])
                #add host to the temporary list of hosts
                h_list.append(host_name)
                self.nmaas_graph.add_node(host_name,
                                          ipv4=host.ipv4,
                                          ipv6=host.ipv6,
                                          mac=host.mac,
                                          connected_to="s-{}".format(host.port.dpid),
                                          port_no=host.port.port_no)
                #add corresponding links to the graph
                self.nmaas_graph.add_edge(host_name,"s-{}".format(host.port.dpid))

        #NOW, REMOVE NODES FROM THE GRAPH WHICH ARE NOT PRESENT IN THE CURRENT TOPOLOGY
        a = list()
        a = s_list + h_list

        diff = list()

        #all nodes in the topology
        #get differences
        diff = list(set(self.nmaas_graph.get_nodes()) - set(a)) # this will produce a list() of the differences

        if len(diff) > 0:
            #remove the additional nodes from the graph
            self.nmaas_graph.remove_nodes_from_list(diff)
            self.log.info("The following nodes have been removed from the graph:")
            print(diff)




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
        dp = msg.datapath
        pkt = packet.Packet(msg.data)


        eth = pkt.get_protocol(ethernet.ethernet)
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        # print eth
        #ignore lldp
        if eth.ethertype in (ETH_TYPE_LLDP, ETH_TYPE_CFM):

            # self.log.info("LLDP packet - ignore")
            return
        else:
            #update topology
            self.update_topology_data()

            dl_src = eth.src
            dl_dst = eth.dst
            in_port = msg.match['in_port']

            self.log.info("DL_SRC:{} to DL_DST:{} via port {} in swith {}".format(dl_src,dl_dst,in_port,dp.id))

            # get the corresponding mac_to_port dictionary for the switch
            mac_table = self.mac_to_ports[dp.id]



            # default output port is flood
            out_port = ofp.OFPP_FLOOD

            # TABLE 0 : in_port + dl_src -> goto table 1
            # TABLE 1 : dl_dst -> outport
            if dl_src not in mac_table:
                self.log.info("SRC_MAC is unknown --> store SRC_MAC and IN_PORT")
                # TABLE 0
                mac_table[dl_src] = in_port
                match = ofp_parser.OFPMatch(in_port=in_port, eth_src=dl_src)
                # actions = [ofp_parser.OFPActionOutput(in_port,0)]
                inst = [ofp_parser.OFPInstructionGotoTable(1)]
                self.send_flow_mod(dp,0,match,inst,buffer_id=msg.buffer_id)

                # # TABLE 1
                # match = ofp_parser.OFPMatch(eth_dst=dl_src)
                # actions = [ofp_parser.OFPActionOutput(in_port,0)]
                # inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                # self.send_flow_mod(dp, 1, match, inst)

                # PATH
                if dl_src not in self.paths:
                    self.paths[dl_src] = list()
                self.paths[dl_src].append(dp.id)


            if dl_dst in mac_table:
                out_port = mac_table[dl_dst]
                self.logger.info("DST_MAC KNOWN --> OUTPUT port is: {}".format(out_port))
                match = ofp_parser.OFPMatch(eth_dst=dl_dst)
                actions = [ofp_parser.OFPActionOutput(out_port)]
                inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                self.send_flow_mod(dp,1,match,inst, buffer_id=msg.buffer_id)
            else:
                self.logger.info("DL_DST IS UNKONWN -> FLOOD")

                actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
                # inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                # self.send_flow_mod(dp, 0, None, inst)
                out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=0xffffffff,
                                          in_port=in_port, actions=actions, data=msg.data)
                dp.send_msg(out)

            # self.log.debug(eth)

        dp = msg.datapath
