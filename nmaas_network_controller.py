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

import copy
import os
from networkx.relabel import _relabel_copy

from eventlet.green import time
from matplotlib import use
from ryu.lib.packet.icmp import dest_unreach
from ryu.lib.packet.vlan import vlan
from ryu.lib.packet import arp
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ether import ETH_TYPE_CFM
from ryu.ofproto.ether import ETH_TYPE_LLDP
from ryu.ofproto.ether import ETH_TYPE_8021Q
from ryu.ofproto.ether import ETH_TYPE_ARP

from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link, get_host
from ryu.controller import ofp_event,dpset
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet,ethernet, vlan
from ryu.app.wsgi import  WSGIApplication
from ryu.base import app_manager

# from nmaas_network_controller_bak import NMaaS_FrameWork
from nmaas_framework import NMaaS_FrameWork, HIGHEST_PRIORITY
from nmaas_rest_api import NMaaS_RESTAPI
from nmaas_network_graph import NMaaS_Network_Graph

#threading
from threading import Condition

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

    # this dictionary stores the lastly added port data for the switches
    switches_recent_ports = dict(dict())  # updated by PORT ADD and DELETE functions

    debug_level = "info"

    def __init__(self, *args, **kwargs):
        super(NMaaS_Network_Controller, self).__init__(*args, **kwargs)
        # get a logger
        self.log = l.getLogger(self.__class__.__name__, self.debug_level)
        self.log.info("UP and RUNNING!")

        self.log.debug("Registering NMaaS RESTAPI")
        wsgi = kwargs['wsgi']
        wsgi.register(NMaaS_RESTAPI,
                      {nmaas_network_controller_instance_name: self})

        #create nmass_network_graph instance
        self.nmaas_graph = NMaaS_Network_Graph(debug_level=self.debug_level) #pass debug level param for logging

        # create nmaas fw instance
        self.nmaas_fw = NMaaS_FrameWork(self, self.nmaas_graph)

        self.topology_api_app = self

        #learning switch
        self.mac_to_ports = dict()

        #nodes
        self.switches = dict()
        self.hosts = dict()

        self.traced_paths = dict()

        self.vlans = list()
        for i in range(1,4095):
            self.vlans.append(i)

        #sort in reverse order
        self.vlans.sort(reverse=True)

        #stores paths and their vlan identifier in the following manner: "h1-h4":"1"
        self.paths_to_vlan = dict()

        #this dictionary will store switch ids as keys, and flowstats data. Only the latest, each time a new flowstat
        #is requested it is going to be updated (e.g., dpid: {count: 14}, ....)
        self.last_flowstats = dict()

        #this number will store how many stats replies has been got, and accordingly, if it equals to the number of
        #switches, it indicates that all data have been gathered and we can continue processing them
        self.number_of_stats_replies = 0    # it will be updated when a switch connects, this is starts from the number
                                            # of switches, and it is increased by one once a reply is received.
        self.cv = Condition()


        #lists for topology data to store always the last status
        self.switch_list = list()
        self.host_list = list()
        self.link_list = list()



    def release_vlan_tag(self, vlan_tag):
        '''
        This function will release the vlan_tag add gives it back to the self.vlans list and re-sort it
        :param vlan_tag: the vlan_tag desired to release
        :return:
        '''
        self.vlans.append(vlan_tag)
        self.vlans.sort(reverse=True)

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


    def install_shortest_path_between_src_dst(self,src,dst):
        paths = self.nmaas_graph.get_all_pair_shortest_paths()
        # paths looks like {h1:{h2:[[path1],[path2]]}} <- EXAMPLE
        p = paths[src][dst][0]
        source_host = self.nmaas_graph.get_node(src)
        source_ip = (source_host['ipv4'][0], '255.255.255.255')
        dst_host = self.nmaas_graph.get_node(dst)
        destination_ip = (dst_host['ipv4'][0], '255.255.255.255')

        self.log.info("PATH is: {}".format(p))
        for num, sw in enumerate(p):
            # print sw
            if sw.startswith('h'):
                # it's a host, skip (this will also prevent running out of indexes in both direction (see below))
                continue

            prev = p[num - 1]
            current = p[num]
            next = p[num + 1]
            self._install_flow_rule_for_chain_link(current, prev, next, source_ip, destination_ip)

    def _install_flow_rule_for_chain_link(self,chain_link, chain_prev, chain_next, source_ip, destination_ip):
        '''
        This function installs flow rules to the given datapath for the given IP addresses. According to the chain_prev
        and chain_next, it gets the link/port number information from the graph that stores them
        :param chain_link: String - the name of the chain_link
        :param chain_prev: String - the name of the previous switch
        :param chain_next: String - the name of the next switch
        :param source_ip: String - the source host IP address for the backward direction
        :param destination_ip: String - the destination IP address for the forward direction
        :return:
        '''

        table_id = 100


        datapath = self.nmaas_graph.get_node(chain_link)['dp']
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        match_source_ip = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst=source_ip)
        match_destination_ip = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_dst=destination_ip)

        # --- backward direction
        # get edge_data
        edge = self.nmaas_graph.get_edge(chain_link, chain_prev)
        print edge
        if edge['dst_dpid'] == chain_link:
            # if prev is a host, then it is always the case that edge['dst_port'] stores the port number
            out_port = edge['dst_port']
        else:
            # if prev is a switch, then it might be the src_dpid
            out_port = edge['src_port']
        actions = [ofp_parser.OFPActionOutput(out_port, 0)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        self.log.info("install flow rule for SIP {} - DIP {} at {} to forward packet on port {}".format(source_ip,
                                                                                                        destination_ip,
                                                                                                        chain_link,
                                                                                                        out_port))
        self.send_flow_mod(datapath, table_id, match_source_ip, inst)

        # --- forward direction
        # get edge_data
        edge = self.nmaas_graph.get_edge(chain_link, chain_next)
        print edge
        if edge['dst_dpid'] == chain_link:
            # if next is a host, then it is always the case that edge['dst_port'] stores the port number
            out_port = edge['dst_port']
        else:
            # if next is a switch, then it might be the src_dpid
            out_port = edge['src_port']
        actions = [ofp_parser.OFPActionOutput(out_port, 0)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        self.log.info("install flow rule for SIP {} - DIP {} at {} to forward packet on port {}".format(source_ip,
                                                                                                        destination_ip,
                                                                                                        chain_link,
                                                                                                        out_port))
        self.send_flow_mod(datapath, table_id, match_destination_ip, inst)

    def install_shortest_paths_flow_rules(self):
        '''
        This function will install flow rules according to the shortest paths
        :return:
        '''
        paths = self.nmaas_graph.get_all_pair_shortest_paths()
        # paths looks like {h1:{h2:[[path1],[path2]]}} <- EXAMPLE
        for source in paths:  # source = h1
            source_host = self.nmaas_graph.get_node(source)
            source_ip = (source_host['ipv4'][0], '255.255.255.255')

            # self.log.info(paths[source])  # paths[source] = {h2: [[path1],[path2]]
            for p in paths[source]:  # p = h2
                destination_host = self.nmaas_graph.get_node(p)
                destination_ip = (destination_host['ipv4'][0], '255.255.255.255')
                for path_num, j in enumerate(paths[source][p]):  # paths[source][p] = [[path1],[path2]], j = one path from paths
                    #install the first rule always! TODO: INSTALL ECMPs/Load-balancers these cases
                    individual_path = j
                    # self.log.info("IndividualPATH:")
                    # self.log.info(individual_path)
                    for num,sw in enumerate(individual_path):
                        # print sw
                        if sw.startswith('h'):
                            # it's a host, skip (this will also prevent running out of indexes in both direction (see below))
                            continue

                        prev = individual_path[num - 1]
                        current = individual_path[num]
                        next = individual_path[num + 1]
                        self._install_flow_rule_for_chain_link(current, prev, next, source_ip, destination_ip)
                    # break #TODO: INSTALL ECMPs/Load-balancers these cases


    def install_flow_rules(self):
        '''
        This function installs initial ARP related flow rules in the switch
        :param datapath: the datapath object, i.e., the switch
        :return:
        '''

        table_id = 100

        self.log.info("Calculating all paths...")
        paths = dict()
        #get all hosts
        hosts = self.nmaas_graph.get_nodes(prefix='h')
        for i in hosts:
            paths[i] = dict()
            for j in hosts:
                if i == j:
                    continue
                paths[i][j]=list()
                self.log.info("get path from {} to {}".format(i,j))
                for path in self.nmaas_graph.get_path(i,j):
                    paths[i][j].append(path)

        self.log.info("PATHS")
        for i in paths:
            print i, paths[i]
        for i in paths:
            for j in paths[i]:
                if i == j:
                    continue
                print "From {} to {}:".format(i,j)
                print paths[i][j]
                # for source host
                source_ip = (self.nmaas_graph.get_node(i)['ipv4'][0], '255.255.255.255')

                # for destination host
                destination_ip = (self.nmaas_graph.get_node(j)['ipv4'][0], '255.255.255.255')

                if len(paths[i][j]) != 1:
                    self.log.warning("There are numerous paths!")

                for p in paths[i][j]:
                    for num, sw in enumerate(p):
                        if sw.startswith('h'):
                            # it's a host, skip (this will also prevent running out of indexes in both direction
                            continue

                        prev = p[num - 1]
                        current = p[num]
                        next = p[num + 1]
                        self._install_flow_rule_for_chain_link(current, prev, next, source_ip, destination_ip)

    def send_get_config_request(self, datapath):
        '''
        Send config request
        :param datapath:
        :return:
        '''
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPGetConfigRequest(datapath)
        self.log.debug("Sending get-config to switch {}".format(datapath.id))
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

            #create flowstats for
            self.last_flowstats["s{}".format(dp.id)] = dict()

            # send flow mods to first hop switch
            # ---- TAGGING ----
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            # untagged traffic will be handled normally
            match = ofp_parser.OFPMatch(vlan_vid=0x0000)
            # actions = [ofp_parser.OFPActionPopVlan()]
            inst = [ofp_parser.OFPInstructionGotoTable(100)]
            self.send_flow_mod(dp, 0, match, inst, buffer_id=0xffffffff, priority=1)


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

    def request_stats(self, datapath, **kwargs):
        '''
        This function sends stat request to the switch specified by datapath
        :param datapath: the datapath from where the stats are required
        :param kwargs: Filters
            flags : flags (default: 0)
            table_id : filter for specific table id (default: OFPTT_ALL)
            out_port : output (default: OFPP_ANY)
            out_group : outgroup (default: OFPG_ANY)
            cookie : cookie (default: 0)
            cookie_mask : cookie_mask (default: 0)
            match: OFPMatch object to filter for (default: None)
        :return:
        '''
        self.log.debug('send stats request: %016x', datapath.id)
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        flags = kwargs.get('flags',0)
        table_id = kwargs.get('table_id', ofp.OFPTT_ALL)
        out_port = kwargs.get('out_port', ofp.OFPP_ANY)
        out_group = kwargs.get('out_group',ofp.OFPG_ANY)
        cookie = kwargs.get('cookie',0)
        cookie_mask = kwargs.get('cookie_mask', 0)
        match = kwargs.get('match', None)


        # match = ofp_parser.OFPMatch(vlan_vid=0x1000 | vlan_id)
        #sending flowstat request
        req = ofp_parser.OFPFlowStatsRequest(datapath,
                                             flags,
                                             table_id,
                                             out_port,
                                             out_group,
                                             cookie,
                                             cookie_mask,
                                             match)
        datapath.send_msg(req)


        #sending portstat request
        # req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        # datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        '''
        This function catches the flow stats replies
        :param ev:
        :return:
        '''

        #decrease number of replies by one
        self.number_of_stats_replies=self.number_of_stats_replies-1

        body = ev.msg.body
        dpid = ev.msg.datapath.id
        ofp = ev.msg.datapath.ofproto
        ofp_parser = ev.msg.datapath.ofproto_parser
        self.log.info("s{} has just responded to flowstats request!".format(dpid))
        sw = 's{}'.format(dpid)

        #if the stats if for table id 0, then it is a first-hop tagging switch
        for stat in body:
            if stat.table_id == 0: #tagging first hop switch
                self.log.debug("{} TAGs traffic".format(sw))
                #get the tagging vlan value
                #there is always one instruction, with 3 actions (push,setvlan,gototable)
                vlan_vid = stat.instructions[0].actions[1].field.value #TODO: this indexes are hardcoded to this use case
                tmp_dict = {'tagging': {vlan_vid : stat.packet_count}}
                                # { "{}-{}".format(stat.match['ipv4_src'], stat.match['ipv4_dst']): #key is IP-IP
                                #       [vlan_vid, stat.packet_count]}} #value:list(vlan_id, packet_count)
                self.last_flowstats[sw]=tmp_dict
            else: #untagging or counting
                # self.log.info("UNTAG OR COUNT")
                #check for untagging
                if not isinstance(stat.instructions[0],ofp_parser.OFPInstructionGotoTable) and isinstance(stat.instructions[0].actions[0], ofp_parser.OFPActionPopVlan):
                    self.log.debug("{} UNTAGs traffic!".format(sw))
                    key = 'untagging'
                else:
                    key = 'counting'
                    self.log.debug("{} COUNTs traffic!".format(sw))


                tmp_dict = {key: {stat.match['vlan_vid']&0xfff : stat.packet_count}} #vlan_id : packet_count
                self.last_flowstats[sw]=tmp_dict



        # # notifiying get_path function's relevant part to start processing of gathered data

        if self.number_of_stats_replies == 0:
            self.cv.acquire()
            self.log.debug("All data gathered from switches...NOTIFYING!")
            self.cv.notify()
            # self.log.info("NOTIFY")
            self.cv.release()


    # ---------- TOPOLOGY UPDATE ----------------
    def update_topology_data(self):
        '''
        This function updates the topology related to hosts and links among switches.
        Switches are in the topology and their statuses are handled in connection up/down event in function connection_handler()
        :return:
        '''
        # self.log.info("Updating topology...")
        #FIRST ADD EVERYTHING TO THE NETWORK (DUPLICATES ARE HANDLED BY DEFAULT)
        #get switch list
        switch_list = list()
        switch_list = get_switch(self.topology_api_app, None)

        # get links and their endpoints
        links_list = get_link(self.topology_api_app, None)

        # get hosts if there is any
        hosts_list = get_host(self.topology_api_app, None)

        if len(switch_list) == 0 and len(links_list) == 0 and len(hosts_list):
            #topology is empty - mininet was stopped
            return


        #temprary lists for switches and hosts
        s_list = list()
        h_list = list()
        l_list = list()

        #variable to store whether topology has been changed compared to the graph
        topology_changed = False

        # update switches in topology
        for switch in switch_list:
            switch_name = "s{}".format(switch.dp.id)
            #add switch to the temporary list of switches
            s_list.append(switch_name)

            #add switchs to graph with preset attribute names
            #define a recent_port data dictionary as an attribute for the swithes - it will be updated in each case
            #a new port comes up
            if switch_name not in self.nmaas_graph.get_nodes():
                recent_port_data = dict()
                self.nmaas_graph.add_node(switch_name,
                                          name=switch_name,
                                          dp=switch.dp,
                                          port=switch.ports,
                                          recent_port_data=recent_port_data)
                topology_changed = True


        #this only goes through the switch links
        for link in links_list:
            # print link
            source = "s{}".format(link.src.dpid)
            target = "s{}".format(link.dst.dpid)
            l_list.append("{}-{}".format(source, target))
            #networkx links in Graph() are not differentiated by source and destination, so a link and its data become
            #updated when add_edge is called with the source and destination swapped
            if self.nmaas_graph.get_graph().has_edge(source, target):
                #once a link is added, we do not readd it, since it just updates the data, but there won'be any new link
                # print("Link {}-{} already added...skipping".format(source, target))
                continue
            # print("Add link {}-{}".format(link.src.dpid,link.dst.dpid))


            self.nmaas_graph.add_edge(source, target,
                                      src_dpid = source, src_port =link.src.port_no,
                                      dst_dpid=target, dst_port = link.dst.port_no)
            topology_changed = True

        # self.log.warning("Number of hosts: {}".format(len(host_list)))
        if hosts_list:
            for host in hosts_list:
                #check whether host has IP address
                if host.ipv4:
                    # #if the ip address of the host corresponds to a module, we name it differently
                    # if host.ipv4[0].startswith("10.{}.".format(self.nmaas_fw.PING_ID)):
                    #     host_name = "PM-{}".format(host.ipv4[0])
                    # else:
                    # we create something like h-1, h-2, etc.
                    host_name = "h{}".format(host.ipv4[0].split(".")[3])
                    #add host to the temporary list of hosts
                    h_list.append(host_name)

                    if host_name not in self.nmaas_graph.get_nodes():
                        self.log.info("Host found - added as {}".format(host_name))
                        self.nmaas_graph.add_node(host_name,
                                              name=host_name,
                                              ipv4=host.ipv4,
                                              ipv6=host.ipv6,
                                              mac=host.mac,
                                              connected_to="s{}".format(host.port.dpid),
                                              port_no=host.port.port_no)
                        #add corresponding links to the graph
                        self.nmaas_graph.add_edge(host_name,"s{}".format(host.port.dpid),
                                                  dst_port = host.port.port_no, dst_dpid="s{}".format(host.port.dpid))
                        topology_changed = True

        # self.log.debug("TOPOLOGY UPDATE")
        # self.log.debug("Switches before: {}".format(self.switch_list))
        # self.log.debug("Switches after: {}".format(s_list))
        # self.switch_list = copy.deepcopy(s_list)
        # self.log.debug("Hosts before: {}".format(self.host_list))
        # self.log.debug("Hosts after: {}".format(h_list))
        # self.host_list = copy.deepcopy(h_list)
        # self.log.debug("Links before: {}".format(self.link_list))
        # self.log.debug("Links after: {}".format(l_list))
        # self.link_list = copy.deepcopy(l_list)

        #NOW, REMOVE NODES FROM THE GRAPH WHICH ARE NOT PRESENT IN THE CURRENT TOPOLOGY
        a = list()
        a = s_list + h_list

        diff = list()

        #all nodes in the topology
        #get differences
        diff = list(set(self.nmaas_graph.get_nodes()) - set(a)) # this will produce a list() of the differences


        if len(diff) > 0:
            #remove the additional nodes from the graph
            for i in diff:
                if not i.startswith('nmaas'): #nmaas hosts are handled differently as they are not mininet hosts
                    self.nmaas_graph.remove_node(i)
                    self.log.info("The following nodes have been removed from the graph:")
                    print(i)
                    topology_changed = True


        if topology_changed: # recalculate shortest paths
            self.nmaas_graph.calculate_all_pair_shortest_paths()
    # ----------------------------------------------


    @set_ev_cls(dpset.EventPortAdd, CONFIG_DISPATCHER)
    def port_add_handler(self, ev):
        dp = ev.dp
        port = ev.port
        self.log.debug("New port has been added to switch {}".format(dp.id))
        self.log.debug("\tno:\t{}".format(port.port_no))
        self.log.debug("\tname:\t{}".format(port.name))
        self.log.debug("\tMAC:\t{}".format(port.hw_addr))
        self.log.debug("\tstate:\t{}".format(port.state))

        # update latest port data
        try:
            self.nmaas_graph.get_node("s{}".format(dp.id))['recent_port_data'] = {
                "port_no": port.port_no,
                "port_name:": port.name,
                "port_hw_addr": port.hw_addr,
                "port_state": port.state
            }
            self.update_topology_data()
        except TypeError as te:
            self.log.debug("port has not state yet, update later...continue processing")

    # ------------ PORT DELETE ------------
    @set_ev_cls(dpset.EventPortDelete, CONFIG_DISPATCHER)
    def port_del_handler(self, ev):
        dp = ev.dp
        port = ev.port
        self.log.debug("New port has been deleted to switch {}".format(dp.id))
        self.log.debug("\tno:\t{}".format(port.port_no))
        self.log.debug("\tname:\t{}".format(port.name))
        self.log.debug("\tMAC:\t{}".format(port.hw_addr))
        self.log.debug("\tstate:\t{}".format(port.state))
        self.update_topology_data()

    # ------------ PORT MODIFY ------------
    @set_ev_cls(dpset.EventPortModify, CONFIG_DISPATCHER)
    def port_mod_handler(self, ev):
        dp = ev.dp
        port = ev.port
        self.log.debug("A port has been modified on switch {}".format(dp.id))
        self.log.debug("\tno:\t{}".format(port.port_no))
        self.log.debug("\tname:\t{}".format(port.name))
        self.log.debug("\tMAC:\t{}".format(port.hw_addr))
        self.log.debug("\tstate:\t{}".format(port.state))
        self.update_topology_data()

    @set_ev_cls(ofp_event.EventOFPGetConfigReply, MAIN_DISPATCHER)
    def get_config_reply_handler(self, ev):
        '''
        get config reply
        :param ev:
        :return:
        '''
        self.log.debug("get-config reply:")
        self.log.debug(ev)
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

        # self.log.info('OFPSwitchFeatures received: '
        #               'datapath_id=0x%016x n_buffers=%d '
        #               'n_tables=%d auxiliary_id=%d '
        #               'capabilities=0x%08x',
        #               msg.datapath_id, msg.n_buffers, msg.n_tables,
        #               msg.auxiliary_id, msg.capabilities)

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

    def create_5tuple_string(self, eth_type, src_ip, src_port, dst_ip, dst_port):
        '''
        This simple function just creates a string from the 5-tuple which format is used across the classes
        :param src_ip: String - source ip 
        :param src_port: String - source port
        :param dst_ip:  String - destination ip
        :param dst_port: String - destination port
        :param eth_type: String - ethernet type
        :return: eth_type-src_ip:src_port->dst_ip:dst_port
        '''
        return "{}-{}:{}->{}:{}".format(eth_type, src_ip, src_port, dst_ip, dst_port)

    def capture_paths(self, src_ip, src_port, dst_ip, dst_port, eth_type):
        #first get the switch where the host_from is connected - this switch will tag the traffic

        to_capture = self.create_5tuple_string(eth_type, src_ip, src_port, dst_ip, dst_port)

        try:
            src_port = int(src_port)
            dst_port = int(dst_port)
        except ValueError:
            self.log.error("The ports you provided are not integer numbers!")
            return

        #eth_type comes as a string, so we convert it to int, then to hex
        eth_type=int(eth_type,16)

        src_host = self.nmaas_graph.get_host_by_ip(src_ip)
        # print src_host
        dst_host = self.nmaas_graph.get_host_by_ip(dst_ip)
        # print dst_host
        if to_capture in self.paths_to_vlan:
            msg = "A path capturing is already set for {}".format(to_capture)
            self.log.info(msg)
            return msg

        shortest_paths_from_to = self.nmaas_graph.get_all_pair_shortest_paths()[src_host['name']][dst_host['name']]
        if len(shortest_paths_from_to) == 1:
            #no multiple paths
            msg = "There is only one path between {} and {}: \n".format(src_host['name'], dst_host['name'])
            msg += self.nmaas_graph.print_path(shortest_paths_from_to[0]) + "\n"
            return msg



        netmask='255.255.255.255' #for exact match
        dst_switch = self.nmaas_graph.get_node(dst_host['connected_to'])


        #this will identify traffic of host_from
        vlan_id = self.vlans.pop()

        #store used vlan id for the requested path
        self.paths_to_vlan[to_capture] = vlan_id


        # ---- ========   UNTAGGING  ========= ----
        #first, we install untagging rule at the last hop switch
        datapath = dst_switch['dp']
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        self.log.info("sending flow_mod to last-hop switch {} to capture traffic of 5-tuple ({},{},{},{},{}) with "
                      "vlan_id {}".format(dst_host['connected_to'],
                                          eth_type,
                                          src_ip,
                                          src_port,
                                          dst_ip,
                                          dst_port,
                                          vlan_id))



        #send flow mods to the last hop switch

        #untagged traffic will be handled normally
        match = ofp_parser.OFPMatch(vlan_vid=0x0000)
        # actions = [ofp_parser.OFPActionPopVlan()]
        inst = [ofp_parser.OFPInstructionGotoTable(100)]
        self.send_flow_mod(datapath, 0, match, inst, buffer_id=0xffffffff, priority=1)

        #packets with vlan tags go to table 1
        match = ofp_parser.OFPMatch(vlan_vid=(0x1000, 0x1000))
        # actions = [ofp_parser.OFPPopVlan()]
        inst = [ofp_parser.OFPInstructionGotoTable(1)]
        self.send_flow_mod(datapath, 0, match, inst, buffer_id=0xffffffff, priority=1000)

        #strip vlan from packets
        match = ofp_parser.OFPMatch(vlan_vid=0x1000| vlan_id)
        actions = [ofp_parser.OFPActionPopVlan()]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,actions),
                ofp_parser.OFPInstructionGotoTable(100)]
        self.send_flow_mod(datapath, 1, match, inst, buffer_id=0xffffffff, priority=1)


        # ---- ========   COUNTING  ========= ----
        #install capture rules to other switch

        rest = list()
        for i in shortest_paths_from_to:
            if len(i) == 3:
                self.log.info("{} is only one hop away from {}".format(src_host['name'],dst_host['name']))
                #the host are only one hop away, no need for counting, as tagging and untagging switch is also the same
                continue
            elif len(i) == 4:
                self.log.info("{} is only 2 hop away from {}".format(src_host['name'],dst_host['name']))
                #each host's switch is directly connected, i.e., no need for counting
                continue
            else:
                in_between = i[2:-2]
                for sw in in_between:
                    #first element is host, second is tagging switch, last element host, penultimate untagging switch
                    #we only need the switches between
                    self.log.info("Installing counting rules for 5-tuple ({},{},{},{},{}) at switch {}".format(
                                  eth_type,
                                  src_ip,
                                  src_port,
                                  dst_ip,
                                  dst_port,
                                  sw))

                    datapath = self.nmaas_graph.get_node(sw)['dp']
                    self.log.info("s{}".format(datapath.id))
                    ofp = datapath.ofproto
                    ofp_parser = datapath.ofproto_parser

                    # every non-tagged traffic
                    match = ofp_parser.OFPMatch(vlan_vid=0x0000)
                    # actions = [ofp_parser.OFPPopVlan()]
                    inst = [ofp_parser.OFPInstructionGotoTable(100)]
                    self.send_flow_mod(datapath, 0, match, inst, buffer_id=0xffffffff, priority=1)

                    # tagged traffic regardless of the value
                    match = ofp_parser.OFPMatch(vlan_vid=(0x1000, 0x1000))
                    # actions = [ofp_parser.OFPPopVlan()]
                    inst = [ofp_parser.OFPInstructionGotoTable(1)]
                    self.send_flow_mod(datapath, 0, match, inst, buffer_id=0xffffffff, priority=1000)

                    # counting table
                    match = ofp_parser.OFPMatch(vlan_vid=(0x1000 | vlan_id))
                    # actions = [ofp_parser.OFPPopVlan()]
                    inst = [ofp_parser.OFPInstructionGotoTable(100)]
                    self.send_flow_mod(datapath, 1, match, inst, buffer_id=0xffffffff, priority=1)


        # ---- ==========   TAGGING   =========== ----
        # tagging tules must be installed last to avoid packet_loss realization: if first switch already tags the packets
        #a priori to installing counting rules and untagging rules, the system will definitely realize this as a packet
        #loss as more tagged packets are going to calculated as untagged
        src_switch = self.nmaas_graph.get_node(src_host['connected_to'])
        datapath = src_switch['dp']
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        self.log.info(
            "sending flow_mod to first-hop switch {} to capture traffic of 5-tuple ({},{},{},{},{}) with "
            "vlan_id {}".format(src_host['connected_to'],
                                eth_type,
                                src_ip,
                                src_port,
                                dst_ip,
                                dst_port,
                                vlan_id))

        # send flow mods to first hop switch
        match = ofp_parser.OFPMatch(eth_type=eth_type,
                                    ip_proto=6,
                                    ipv4_src=(src_ip, netmask),
                                    ipv4_dst=(dst_ip, netmask),
                                    tcp_src=src_port,
                                    tcp_dst=dst_port)
        f = ofp_parser.OFPMatchField.make(
            ofp.OXM_OF_VLAN_VID, vlan_id)

        actions = [ofp_parser.OFPActionPushVlan(ETH_TYPE_8021Q),
                   ofp_parser.OFPActionSetField(f)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
                ofp_parser.OFPInstructionGotoTable(100)]
        self.send_flow_mod(datapath, 0, match, inst, buffer_id=0xffffffff, priority=1000)

        # direct every other traffic to table 100 as well
        # untagged traffic will be handled normally
        match = ofp_parser.OFPMatch(vlan_vid=0x0000)
        # actions = [ofp_parser.OFPActionPopVlan()]
        inst = [ofp_parser.OFPInstructionGotoTable(100)]
        self.send_flow_mod(datapath, 0, match, inst, buffer_id=0xffffffff, priority=1)



                # print out the possible paths
        msg = "Possible paths:\n"

        for i,path in enumerate(shortest_paths_from_to):
            msg += "{}: {}\n".format(i, self.nmaas_graph.print_path(path))
        self.log.info(msg)
        return msg


    # --------- DELETING A FLOW RULE -------------
    def remove_flow(self,datapath, table_id, match, **args):
        '''
        This function removes a flow from the given datapath
        :param datapath: the datapath element
        :param table_id: the id of the table that consists of the flow rule
        :param match: OFPMatch element
        :param args: further arguments possible to set for OFPFlowMod
        :return: 
        '''
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = args.get('cookie', 0)
        cookie_mask = args.get('cookie_mask', 0)
        idle_timeout = args.get('idle_timeout', 0)
        hard_timeout = args.get('hard_timeout', 0)
        priority = args.get('priority', 1000)
        buffer_id = args.get('buffer_id', ofp.OFP_NO_BUFFER)
        mod_type = args.get('mod_type', ofp.OFPFC_DELETE)
        flag = args.get('flags', ofp.OFPFF_SEND_FLOW_REM)
        instructions = args.get('instructions', [])


        req = ofp_parser.OFPFlowMod(datapath,
                                    cookie,
                                    cookie_mask,
                                    table_id,
                                    mod_type,
                                    idle_timeout,
                                    hard_timeout,
                                    priority,
                                    buffer_id,
                                    ofp.OFPP_ANY,
                                    ofp.OFPG_ANY,
                                    ofp.OFPFF_SEND_FLOW_REM,
                                    match,
                                    instructions)

        datapath.send_msg(req)




    # ---------- GETTING THE PRACTICAL PATHS ------------
    def get_paths(self, src_ip, src_port, dst_ip, dst_port, eth_type):
        '''
        This function will gives the list of switches that took part in the packet forwarding
        :param host_from: the source host
        :param host_to:  the destination host
        :return:
        '''

        to_capture = self.create_5tuple_string(eth_type, src_ip, src_port, dst_ip, dst_port)

        try:
            src_port = int(src_port)
            dst_port = int(dst_port)
        except ValueError:
            self.log.error("The ports you provided are not integer numbers!")
            return

        # eth_type comes as a string, so we convert it to int, then to hex
        eth_type = int(eth_type, 16)

        src_host = self.nmaas_graph.get_host_by_ip(src_ip)
        # print src_host
        dst_host = self.nmaas_graph.get_host_by_ip(dst_ip)

        number_of_switches_involved = 1 #there is always at least one switch in the path

        if src_host is None or dst_host is None:
            msg = "Source or destination host does not exists!"
            self.log.error(msg)
            return msg

        if to_capture not in self.paths_to_vlan:
            msg = "There was not trace capture set up for 5-tuple ({},{},{},{},{})!".format(eth_type,
                                                                                            src_ip,
                                                                                            src_port,
                                                                                            dst_ip,
                                                                                            dst_port)
            self.log.error(msg)
            return msg

        #first, get the vlan id, which identifies the paths
        vlan_id = self.paths_to_vlan[to_capture]


        #Then, get the source switch that tags the packet
        first_hop_switch = self.nmaas_graph.get_node(src_host['connected_to'])
        dp = first_hop_switch['dp']
        ofp_parser = dp.ofproto_parser

        netmask='255.255.255.255'
        first_hop_match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_src=(src_ip,netmask), ipv4_dst=(dst_ip,netmask))
        self.log.debug("sending request to first-hop-switch ({})".format(src_host['connected_to']))
        self.request_stats(dp, match=first_hop_match, table_id=0)

        #Next, get the last-hop switch that untags the packets
        last_hop_switch = self.nmaas_graph.get_node(dst_host['connected_to'])
        if last_hop_switch == first_hop_switch:
            #hosts are only 1 hop away. TODO: tag and untag rules for the same traffic at the same switch are not handled
            msg = "{} and {} are attached to the same switch {}".format(src_host['name'],dst_host['name'],last_hop_switch)
            self.log.warning(msg)
            return msg
        dp = last_hop_switch['dp']
        ofp_parser = dp.ofproto_parser
        last_hop_match = ofp_parser.OFPMatch(vlan_vid=0x1000 | vlan_id)
        self.log.debug("sending request to last-hop-switch ({})".format(dst_host['connected_to']))
        self.request_stats(dp, match=last_hop_match, table_id=1)
        #update number of switches whereto requests will be sent
        number_of_switches_involved+=1

        #Last, but not least get the counting switches
        shortest_paths_from_to = self.nmaas_graph.get_all_pair_shortest_paths()[src_host['name']][dst_host['name']]
        rest = list()
        for i in shortest_paths_from_to:
            if len(i) == 3:
                self.log.info("{} is only one hop away from {}".format(src_host['name'], dst_host['name']))
                # the host are only one hop away, no need for counting, as tagging and untagging switch is also the same
                continue
            elif len(i) == 4:
                self.log.info("{} is only 2 hop away from {}".format(src_host['name'], dst_host['name']))
                # each host's switch is directly connected, i.e., no need for counting
                continue
            else:
                in_between = i[2:-2]
                for sw in in_between:
                    #check whether switch was not already added, as one switch may present in numerous paths
                    if sw not in rest:
                        rest.append(sw)
                        dp = self.nmaas_graph.get_node(sw)['dp']
                        ofp = dp.ofproto
                        ofp_parser = dp.ofproto_parser
                        self.log.info("sending request to s{}".format(dp.id))
                        match = ofp_parser.OFPMatch(vlan_vid=0x1000 | vlan_id)
                        self.request_stats(dp, match=match, table_id=1)
                        # update number of switches whereto requests will be sent
                        number_of_switches_involved += 1



        # update possible number_of_replies
        self.number_of_stats_replies = number_of_switches_involved

        #wait until all switches have replied
        self.cv.acquire()
        self.log.debug("Waiting for all data to be gathered...")
        while self.number_of_stats_replies != 0:
            self.cv.wait()
        self.cv.release()


        self.log.debug("LAST FLOW STATS")
        # self.log.info(self.last_flowstats)
        # print(source_host['connected_to'])
        # print(vlan_id)
        tagging_switch = src_host['connected_to']
        tagged_packets = self.last_flowstats[src_host['connected_to']]['tagging'][vlan_id]
        self.log.info("First-hop switch {} tagged  {} packets:".format(tagging_switch, tagged_packets))

        untagging_switch = dst_host['connected_to']
        untagged_packets = self.last_flowstats[dst_host['connected_to']]['untagging'][vlan_id]
        self.log.info("Last-hop switch {} untagged {} packets:".format(untagging_switch, untagged_packets))

        if(tagged_packets != untagged_packets):
            self.log.warning("There was a packet loss of {} packets".format(abs(tagged_packets-untagged_packets)))

        in_between = list()
        for sw in rest:
            if self.last_flowstats[sw]['counting'][vlan_id]:
                #we found a counting switch for the given vlan id
                counting_switch = sw
                counting_packets = self.last_flowstats[sw]['counting'][vlan_id]
                self.log.info("Counting switch {} encountered {} packets".format(
                                        sw,
                                        counting_packets))
                if counting_packets != 0:
                    print "appending {} to in_between".format(sw)
                    in_between.append(sw)
        self.log.debug("------ ALL FLOW STATS -------")
        print(self.last_flowstats)

        # print(in_between)
        #delete capture rules
        self.log.info("Deleting capture rules")
        #first hop switch - tagging
        self.remove_flow(first_hop_switch['dp'], 0, first_hop_match, priority=1000)
        self.log.info("First hop switch cleared")
        # last hop switch - untagging
        self.remove_flow(last_hop_switch['dp'], 1, last_hop_match, priority=1)
        self.log.info("Last hop switch cleared")
        # counting switches
        for counting_switch in in_between:
            dp = self.nmaas_graph.get_node(sw)['dp']
            match = ofp_parser.OFPMatch(vlan_vid=0x1000 | vlan_id)
            self.remove_flow(dp, 1, match, priority=1)
            self.log.info("Counting switch {} cleared".format(sw))

        #releasing used vlan tag
        self.vlans.append(vlan_id)
        self.paths_to_vlan.pop(to_capture)

        path = [src_host['name'], first_hop_switch['name']]
        #construct path
        self.log.info("Reconstructing path")
        path_and_remains = self._construct_path(first_hop_switch['name'], in_between, path)
        while len(path_and_remains[1]) > 0: #there is still switches remaining
            path_and_remains = self._construct_path(path_and_remains[0][-1],path_and_remains[1], path_and_remains[0])
        self.log.info("Path reconstructed")
        path = path_and_remains[0]
        path.append(last_hop_switch['name'])
        path.append(dst_host['name'])
        # print path

        # store the traced path
        self.traced_paths[to_capture] = path

        msg = " -- Path:\n"
        msg += self.nmaas_graph.print_path(path)
        msg += "\n"
        self.log.info(msg)
        return msg



    def _check_neighbor(self,source,nexthop):
        self.log.debug("check neighbor {} and {}".format(source,nexthop))
        return self.nmaas_graph.get_edge(source,nexthop)



    def _construct_path(self, source, node_list, already_known_path):
        for sw in node_list:
            # check whether it is a neighbor of the previously known switch, i.e., at the beginning the first-hop switch
            if self._check_neighbor(source, sw) is not None:
                already_known_path.append(sw)
                break
            else:
                continue

        #broke - node list is updated, we take out the found element, and for this we use the already_known_path list
        #as the last found element is appended to the end of the list just before break
        node_list.pop(node_list.index(already_known_path[-1]))

        #return with the new path, and the list of the remaining switches as a list
        return [already_known_path,node_list]

        # #call recursively this function again if there is still some node
        # if len(node_list) > 0:
        #     self._construct_path(already_known_path[-1],node_list, already_known_path)
        # else:
        #     return already_known_path



    # ------------ PACKET_IN ------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        vlan = False
        arp = False
        icmp = False
        lldp = False

        msg = ev.msg
        in_port = msg.match['in_port']
        dp = msg.datapath
        pkt = packet.Packet(msg.data)
        buffer_id = msg.buffer_id

        # print pkt
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        # print pkt.get_protocol(arp)

        # print eth
        #ignore lldp
        if pkt_eth.ethertype in (ETH_TYPE_LLDP, ETH_TYPE_CFM):
            # self.log.info("LLDP packet - ignore")
            pass
        elif pkt_eth.ethertype == 2054:
            self._handle_arp(dp, in_port, pkt, buffer_id)

        # else:
        #     # pass
        #     dl_src = pkt_eth.src
        #     dl_dst = pkt_eth.dst
        #
        #
        #     idle_timeout = 0
        #
        #     # self.log.info("DL_SRC:{} to DL_DST:{} via port {} in swith {}".format(dl_src,dl_dst,in_port,dp.id))
        #
        #     # get the corresponding mac_to_port dictionary for the switch
        #     mac_table = self.mac_to_ports[dp.id]
        #
        #
        #
        #     # default output port is flood
        #     out_port = ofp.OFPP_FLOOD
        #
        #     # TABLE 0 : in_port + dl_src -> goto table 1
        #     # TABLE 1 : dl_dst -> outport
        #     if dl_src not in mac_table:
        #         if dl_src.startswith("be:ef:be:ef"):
        #             #it is a module, so the idle timeout should be set
        #             idle_timeout = 4
        #
        #         self.log.info("SRC_MAC is unknown --> store SRC_MAC and IN_PORT")
        #         # TABLE 0
        #         mac_table[dl_src] = in_port
        #         # match = ofp_parser.OFPMatch(in_port=in_port, eth_src=dl_src)
        #         match = ofp_parser.OFPMatch(eth_src=dl_src)
        #         # actions = [ofp_parser.OFPActionOutput(in_port,0)]
        #         inst = [ofp_parser.OFPInstructionGotoTable(101)]
        #         self.send_flow_mod(dp,100,match,inst,buffer_id=msg.buffer_id,idle_timeout=idle_timeout)
        #
        #
        #         # # TABLE 1
        #         # match = ofp_parser.OFPMatch(eth_dst=dl_src)
        #         # actions = [ofp_parser.OFPActionOutput(in_port,0)]
        #         # inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        #         # self.send_flow_mod(dp, 1, match, inst)
        #
        #         # # PATH
        #         # if dl_src not in self.paths:
        #         #     self.paths[dl_src] = list()
        #         # self.paths[dl_src].append(dp.id)
        #
        #
        #     if dl_dst in mac_table:
        #         if dl_dst.startswith("be:ef:be:ef"):
        #             idle_timeout = 4
        #         out_port = mac_table[dl_dst]
        #         self.logger.debug("DST_MAC KNOWN --> OUTPUT port is: {}".format(out_port))
        #         match = ofp_parser.OFPMatch(eth_dst=dl_dst)
        #         actions = [ofp_parser.OFPActionOutput(out_port)]
        #         inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        #         self.send_flow_mod(dp,101,match,inst, buffer_id=msg.buffer_id, idle_timeout=idle_timeout)
        #
        #     # else:
        #     #     self.logger.debug("DL_DST IS UNKONWN -> FLOOD")
        #     #
        #     #     actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        #     #     # inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        #     #     # self.send_flow_mod(dp, 0, None, inst)
        #     #     out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=0xffffffff,
        #     #                               in_port=in_port, actions=actions, data=msg.data)
        #     #     dp.send_msg(out)
        #

        # update topology
        self.update_topology_data()

    def _handle_arp(self, dp, in_port, full_packet, buffer_id):
        self.log.debug("ARP packet catched")
        pkt_ethernet = full_packet.get_protocol(ethernet.ethernet)

        pkt = packet.Packet()

        #the full ethernet packet's second part is the ARP related part
        # print full_packet

        src_ip = full_packet[1].src_ip
        dst_ip = full_packet[1].dst_ip
        dl_src = full_packet[1].src_mac

        # print "src_ip:{}, dst_ip:{}".format(src_ip,dst_ip)

        source_host = self.nmaas_graph.get_host_by_ip(src_ip)
        destination_host = self.nmaas_graph.get_host_by_ip(dst_ip)

        if source_host is None or destination_host is None:
            print
            self.log.warning("Hosts are not known to the controller (yet)")
            return

        self.log.info("{} is looking for the MAC of {}".format(source_host['name'],destination_host['name']))

        dl_dst = destination_host['mac']
        # pass

        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=dl_src,
                                           src=dl_dst))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=dl_dst,
                                 src_ip=dst_ip,
                                 dst_mac=dl_src,
                                 dst_ip=src_ip))
        self._send_packet(dp, in_port, pkt)





    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        # self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
