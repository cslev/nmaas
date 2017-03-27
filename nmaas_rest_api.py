from webob.static import DirectoryApp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
import os
import logger as l

# ----------- ============= REST API FOR TENANT-CONTROLLER COMMUNICATION ============== -------------
PATH = os.path.dirname(__file__)
nmaas_network_controller_instance_name = 'nmaas_network_controller_instance_name'
latency_url = '/measurement/latency-hop-by-hop/{host_from}/{host_to}'
class NMaaS_RESTAPI(ControllerBase):
    '''
    This class is devoted to describe a REST API for tenant-controller communications
    '''

    def __init__(self, req, link, data, **config):
        super(NMaaS_RESTAPI, self).__init__(req, link, data, **config)
        self.nmaas_network_controller_app = data[nmaas_network_controller_instance_name]

        path = "%s/html/" % PATH
        print path
        self.static_app = DirectoryApp(path)
        self.nmaas = self.nmaas_network_controller_app
        self.log = l.getLogger(self.__class__.__name__, self.nmaas.debug_level)

    @route('root', '/', methods=['GET'])
    def root(self, req, **kwargs):
        msg =  "--- NMaaS Controller ---\nThe following REST API calls could be issued:\n"
        msg += "  - /topology/update : manually send an update request for the (graph) topology\n"
        msg += "  - /topology/graph : Prints out the known topology information\n"
        msg += "  - /topology/path/{from}/{to} : Returns all possible paths between from and to\n"
        msg += "  - /topology/shortest_paths: Returns all shortest paths\n"
        msg += "  - /topology/install_shortest_paths: Installs shortest paths\n"
        msg += "  - /topology/calculate_paths : Calculates all paths among the nodes and install L3 flow rules " \
               "according to the first found path\n"
        msg += "  - /topology/draw : Draws the current network into /tmp/simple.png\n"
        msg += "  - /nmaas/capture_paths/{from}/{to} : NMaaS will install vlan-based capture rules in the switches for " \
               "the given hosts defined by from and to\n"
        msg += "  - /nmaas/get_paths/{from}/{to} : According to the capture rules, NMaaS gives you the paths and also " \
               "prints out the number of lost packets\n"
        return msg

    @route('topology_update', '/topology/update', methods=['GET'])
    def topology_update(self, req, **kwargs):
        self.nmaas.update_topology_data()

    @route('topology_data_graph', '/topology/graph', methods=['GET'])
    def get_topology_graph(self, req, **kwargs):
        retVal = self.nmaas.nmaas_graph
        self.log.info(retVal)
        return retVal

    @route('topology_calculate_paths', '/topology/calculate_paths', methods=['GET'])
    def calculate_paths(self, req, **kwargs):
        self.nmaas.install_flow_rules()

    @route('topology_install_shortest_paths', '/topology/install_shortest_paths', methods=['GET'])
    def install_shortest_paths(self, req, **kwargs):
        self.nmaas.install_shortest_paths_flow_rules()

    @route('topology_get_path', '/topology/path/{from}/{to}', methods=['GET'])
    def get_path(self,req, **kwargs):
        src=kwargs.get('from', 'h1')
        dst=kwargs.get('to', 'h3')
        path = self.nmaas.nmaas_graph.get_path(src,dst)
        if path is None:
            msg = "Source or destination is not present in the network\n"
            self.log.error(msg)
            return msg
        self.log.info(path)
        retval = ""
        if len(path) == 1:
            for n,i in enumerate(path):
                if n < (len(path)-1):
                    retval+="{} -> ".format(i)
                else:
                    retval += "{}\n".format(i)
        else:
            for p in path:
                for n, i in enumerate(p):
                    if n < (len(p) - 1):
                        retval += "{} -> ".format(i)
                    else:
                        retval += "{}\n".format(i)
        return retval



    @route('topology_get_shortest_path', '/topology/shortest_paths', methods=['GET'])
    def get_shortest_path(self, req, **kwargs):
        msg = ""
        paths = self.nmaas.nmaas_graph.get_all_pair_shortest_paths()
        #paths looks like {h1:{h2:[[path1],[path2]]}} <- EXAMPLE
        for source in paths:  # source = h1
            self.log.info(paths[source]) # paths[source] = {h2: [[path1],[path2]]
            for p in paths[source]: # p = h2
                msg += source + " -> "
                msg += p + ":\n"
                for path_num,j in enumerate(paths[source][p]): #paths[source][p] = [[path1],[path2]], j = one path from paths
                    msg += "{}: ".format(path_num)
                    individual_path_length = len(j)-1
                    for chain_link_num, c in enumerate(j):
                        if chain_link_num < individual_path_length:
                            msg += c+"->"
                        else:
                            msg += c
                    msg += "\n"
        self.log.info(msg)
        return msg


    @route('mac_tables', '/mactables', methods=['GET'])
    def get_mac_tables(self, req, **kwargs):
        nmaas = self.nmaas_network_controller_app
        self.log.info(nmaas.mac_to_ports)

    @route('draw_network', '/topology/draw', methods=['GET'])
    def drwaw_network(self, req, **kwargs):
        image_path = self.nmaas.nmaas_graph.draw_graph()
        # return image_path

    @route('get_paths', '/nmaas/get_paths/{host_from}/{host_to}', methods=['GET'])
    def get_paths(self, req, **kwargs):
        nmaas = self.nmaas_network_controller_app
        # parsing GET to get {host_from} and {host_to}
        host_from = kwargs.get('host_from', None)
        host_to = kwargs.get('host_to', None)
        if not host_from or not host_to:
            return "No source and/or destination was set"
        return self.nmaas.get_paths(host_from, host_to)


    @route('capture_paths', '/nmaas/capture_paths/{host_from}/{host_to}', methods=['GET'])
    def capture_paths(self, req, **kwargs):
        nmaas = self.nmaas_network_controller_app
        # parsing GET to get {host_from} and {host_to}
        host_from = kwargs.get('host_from', None)
        host_to = kwargs.get('host_to', None)
        if not host_from or not host_to:
            return "No source and/or destination was set"

        return self.nmaas.capture_paths(host_from, host_to)

    @route('hop-by-hop-latency', latency_url, methods=['GET'] )
    def calculate_latency(self, req, **kwargs):
        nmaas = self.nmaas_network_controller_app

        # parsing GET to get {host_from} and {host_to}
        host_from = kwargs.get('host_from',"h1")
        host_to = kwargs.get('host_to', "h3")

        #check whether host exists
        if host_from not in nmaas.nmaas_graph.get_nodes():
            msg= "\nUnknown host {}\n".format(host_from)
            self.log.error(msg)
            return msg
        elif host_to not in nmaas.nmaas_graph.get_nodes():
            msg= "\nUnknown host {}\n".format(host_to)
            self.log.error(msg)
            return msg
        else:

            #registering request
            latencies = list()

            self.log.info("\nCalculating hop-by-hop latency between {} and {}\n".format(host_from,host_to))
            path = nmaas.nmaas_graph.get_path(host_from, host_to)
            self.log.info("The path is:\n{}".format(path))

            path=path[1:-1]
            hop_count = len(path) - 1
            # path = nmaas.paths[host_from][host_to]
            for i,sw in enumerate(path):
                # print sw
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
                                                from_to="{}-{}".format(host_from, host_to),
                                                estimated_time=(hop_count+1)*4)

            # namespaces and forwarding rules are installed -> Let's do the pings
            self.log.info("Hop-by-hop measurement is ON!")
            # hop_count = len(nmaas.paths[host_from][host_to]) - 1
            self.log.info("It will take approx. {} seconds".format((hop_count+1)*4))

            # path = nmaas.paths[host_from][host_to]
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



