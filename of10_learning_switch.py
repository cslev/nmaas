from ryu.base import app_manager
from ryu.controller import ofp_event,dpset
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
import array
#for debug purposes to print out all fields, dictionary keys, etc.
from pprint import pprint

#for packet header analysis
from ryu.lib.packet import packet,ethernet

class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    mac_to_ports = dict()

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        # store mac to port mappings for all switches

    # @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    # def switch_features_handler(self, ev):
    #     pprint(vars(ev))


    # ------------ SWITCH CONNECTED ----------
    @set_ev_cls(dpset.EventDP, CONFIG_DISPATCHER)
    def connection_handler(self, ev):
        # pprint(vars(ev))
        enter_leave = ev.enter
        dp = ev.dp
        ports = ev.ports
        # print("Enterr_leave: {}".format(enter_leave))
        if enter_leave == True:
            print("Switch with datapath id {} has been connected".format(dp.id))
            if dp.id not in self.mac_to_ports:
                self.mac_to_ports[dp.id] = dict()
        else:
            print("Switch with datapath id {} has been disconnected".format(dp.id))
            if dp.id in self.mac_to_ports:
                self.mac_to_ports.pop(dp.id)

        print("mac_to_ports:{}".format(self.mac_to_ports))

    # ------------ PORT ADD ------------
    @set_ev_cls(dpset.EventPortAdd, CONFIG_DISPATCHER)
    def port_add_handler(self, ev):
        dp = ev.dp
        port = ev.port
        print("New port has been added to switch {}".format(dp.id))
        print("\tno:\t{}".format(port.port_no))
        print("\tname:\t{}".format(port.name))
        print("\tMAC:\t{}".format(port.hw_addr))
        print("\tstate:\t{}".format(port.state))

    # ------------ PORT DELETE ------------
    @set_ev_cls(dpset.EventPortDelete, CONFIG_DISPATCHER)
    def port_del_handler(self, ev):
        dp = ev.dp
        port = ev.port
        print("New port has been deleted to switch {}".format(dp.id))
        print("\tno:\t{}".format(port.port_no))
        print("\tname:\t{}".format(port.name))
        print("\tMAC:\t{}".format(port.hw_addr))
        print("\tstate:\t{}".format(port.state))

    # ------------ PORT MODIFY ------------
    @set_ev_cls(dpset.EventPortModify, CONFIG_DISPATCHER)
    def port_mod_handler(self, ev):
        dp = ev.dp
        port = ev.port
        print("A port has been modified on switch {}".format(dp.id))
        print("\tno:\t{}".format(port.port_no))
        print("\tname:\t{}".format(port.name))
        print("\tMAC:\t{}".format(port.hw_addr))
        print("\tstate:\t{}".format(port.state))

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
        self.logger.debug('OFPGetConfigReply received: '
                          'flags=%s miss_send_len=%d',
                          flags, msg.miss_send_len)

    # @set_ev_cls(ofp_event.EventOFPPortStateChange, MAIN_DISPATCHER)
    # def port_change_handler(self, dp, reason, port_no):
    #     print("Port state change event from dp: {}".dp)
    #     print("Port number: {}".format(port_no))
    #     print("Reason: {}".format(reason))


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        vlan = False
        arp = False
        icmp = False

        print("\nPacket_IN")
        msg = ev.msg
        dp = msg.datapath
        print("...from DpId:\t{}".format(dp.id))


        pkt = packet.Packet(array.array('B', ev.msg.data))
        for p in pkt.protocols:
            # print p.protocol_name, p
            if p.protocol_name == 'vlan':
                # print("Packet has a VLAN (vid: {}".format(p.vid))
                vlan = True
            elif p.protocol_name == 'arp':
                arp = True
                # print("Packet is ARP")
            elif p.protocol_name == 'icmp':
                icmp = True
                # print("ICMP packet")
            else:
                continue
                # print("Normal packet ?")
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        #learn phase
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        print("msg.data:{}".format(pkt_ethernet))

        # getting src mac and in_port info
        src_mac = pkt_ethernet.src
        dst_mac = pkt_ethernet.dst
        in_port = msg.in_port


        #get the corresponding mac_to_port dictionary for the switch
        mac_table = self.mac_to_ports[dp.id]




        #default output port is flood
        out_port=ofp.OFPP_FLOOD

        if src_mac not in mac_table:
            self.logger.info("SRC_MAC is unknown --> store SRC_MAC and IN_PORT")
            mac_table[src_mac] = in_port
            self.logger.info("assemble match")
            match = ofp_parser.OFPMatch(dl_dst=src_mac)

            self.logger.info("assemble flow mod")
            output = ofp_parser.OFPFlowMod(dp, match=match, cookie=0, command=ofp.OFPFC_ADD, idle_timeout=0,
                                            hard_timeout=0, priority=32768,
                                            buffer_id=0xffffffff, out_port=ofp.OFPP_NONE, flags=0,
                                            actions=[ofp_parser.OFPActionOutput(in_port)])


        if dst_mac in mac_table:
            out_port = mac_table[dst_mac]
            self.logger.info("DST_MAC KNOWN --> OUTPUT port is: {}".format(out_port))
            match = ofp_parser.OFPMatch(dl_dst=dst_mac)
            output = ofp_parser.OFPFlowMod(dp, match=match, cookie=0, command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                                            priority=32768,
                                            buffer_id=0xffffffff, out_port=ofp.OFPP_NONE, flags=0,
                                            actions=[ofp_parser.OFPActionOutput(out_port)])

        # check src_mac existence, if there is no saved src_mac we store that as well
        else:
            output = ofp_parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port, actions=[ofp_parser.OFPActionOutput(out_port)])

        # if arp:


        # match = ofp_parser.OFPMatch(dl_dst=)

        #

        dp.send_msg(output)
        # print("packet_out sent")


