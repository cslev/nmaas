from webob.static import DirectoryApp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
import os

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

    @route('mac_tables', '/mactables', methods=['GET'])
    def get_mac_tables(self, req, **kwargs):
        nmaas = self.nmaas_network_controller_app
        print nmaas.mac_to_ports
        print "---===---"
        print nmaas.paths

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



