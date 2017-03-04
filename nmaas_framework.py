import logger as l
import invoke as invoke
from ryu.ofproto import ofproto_v1_3

HIGHEST_PRIORITY = 1000


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
