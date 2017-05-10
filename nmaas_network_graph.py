import networkx as nx
import inspect
from networkx.algorithms.shortest_paths.weighted import all_pairs_dijkstra_path
import logger as l

try:
    import matplotlib.pyplot as plt
except:
    raise

class NMaaS_Network_Graph():

    def __init__(self, **kwargs):
        self._G=nx.Graph()
        self.shortest_paths = None
        self.log = l.getLogger(self.__class__.__name__, kwargs.get('debug_level', 'INFO'))

    def __str__(self):
        graph_desc = "--- === Graph data === ---\n"
        graph_desc += " -- Nodes --\n"

        for node in self._G.nodes():
            graph_desc += "{}:\n".format(node)

            if node.startswith('h') or node.startswith('nmaas'):
                for i in self._G.node[node]:
                    graph_desc += "  {}:{}\n".format(i,self._G.node[node][i])
            elif node.startswith('s'):
                graph_desc += "  dp: {}\n".format(self._G.node[node]['dp'])
                graph_desc += "  (extracted datapath_id: {})\n".format(self._G.node[node]['dp'].id)
                graph_desc += "  port:\n"
                for port in self._G.node[node]['port']:
                    graph_desc += "    {}\n".format(port)
                graph_desc += "  recent_port_data:\n"
                for i in self._G.node[node]['recent_port_data']:
                    graph_desc += "    {}:{}\n".format(i,self._G.node[node]['recent_port_data'][i])

            else:
                #another kind of node. Currently, we do not have any other type
                pass
            # if node.startswith('s-'):
                #     #switches has more data
                #     graph_desc += "Datapath:{}\n".format(self._G.node[node][i].dp)
                #     graph_desc += "Port:{}\n".format(self._G.node[node][i].ports)

            graph_desc += "\n"

        graph_desc += "\n -- Edges --\n"
        self.log.info(self._G.edges())
        for edge in self._G.edges():
            graph_desc += "Between {} and {}:\n".format(edge[0], edge[1])
            graph_desc += "  {}\n".format(self._G.edge[edge[0]][edge[1]])

        graph_desc += "--------------------\n"

        return graph_desc


    def add_node(self, node, **kwargs):
        self._G.add_node(node, kwargs)


    def remove_node(self, node):
        self._G.remove_node(node)

    def add_nodes_from_list(self, list_of_nodes, **kwargs):
        self._G.add_nodes_from(list_of_nodes)

    def remove_nodes_from_list(self, list_of_nodes):
        self._G.remove_nodes_from(list_of_nodes)

    def get_node(self, node):
        try:
            n = self._G.node[node]
            # print "Node {} got...returning".format(node)
            return n
        except KeyError as e:
            # print "Node {} not found".format(node)
            print e

            return None


    def get_host_by_ip(self, ip):
        '''
        This function finds a host with the given IP and returns it
        :param ip:
        :return:
        '''
        retVal = None
        for i in self.get_nodes(prefix='h'):
            if self._G.node[i]['ipv4'][0] == ip:
                retVal = self._G.node[i]
                return retVal

        if retVal is None:
            #it wasn't a host, it might be an nmaas module
            for i in self.get_nodes(prefix='nmaas'):
                if self._G.node[i]['ipv4'][0] == ip:
                    retVal = self._G.node[i]
                    return retVal
        return None


    def get_nodes(self, **kwargs):
        '''
        This will return all nodes in a list except prefix is not defined in kwargs, which could be 's' indicating
        switches, or 'h' indicating host, or any other special prefix, respectively
        :param kwargs: prefix : 's', 'h', 'PM-' ...
        :return: list of nodes
        '''
        prefix = kwargs.get('prefix', None)
        if not prefix:
            return self._G.nodes()

        retList = list()
        for i in self._G.nodes():
            if i.startswith(prefix):
                retList.append(i)

        return retList


    def add_edge(self, src, dst, **kwargs):
        self._G.add_edge(src, dst, kwargs)

    def remove_edge(self, src, dst):
        self._G.remove_edge(src, dst)

    def add_edges_from_list(self, list_of_src_dst_pairs, **kwargs):
        self._G.add_edges_from(list_of_src_dst_pairs, kwargs)

    def remove_edges_from_list(self, list_of_src_dst_pairs):
        self._G.remove_edges_from(list_of_src_dst_pairs)

    def get_edge(self, src, dst):
        try:
            e = self._G.edge[src][dst]
            return e
        except KeyError:
            return None

    def get_edges(self):
        return self._G.edges()

    def clear_graph(self):
        self._G.clear()

    def get_graph(self):
        return self._G



    def get_path(self,src, dst):
        '''
        This function returns all paths between the given source and destination node
        :param src: String - the source node's name
        :param dst: String - the destination node's name
        :return: list of lists
        '''
        if src not in self._G.nodes() or dst not in self._G.nodes():
            return None

        paths = list()
        try:
            all_sp = nx.all_simple_paths(self._G, src, dst)
            for path in all_sp:
                paths.append(path)
        except nx.NetworkXNoPath: #no path between src and dst
            return None
            # return path

        return paths

    def _get_shortest_paths(self, src, dst):
        '''
        This private function returns all shortest paths between the given source and destination node
        :param src: String - the source node's name
        :param dst: String - the destination node's name
        :return: list of lists
        '''
        if src not in self._G.nodes() or dst not in self._G.nodes():
            return None
        paths = list()
        try:
            all_sp = nx.all_shortest_paths(self._G, src, dst)
            for path in all_sp:
                paths.append(path)

        except nx.NetworkXNoPath: #no path between src and dst
            return None

        return paths

    def print_path(self, list_of_path):
        '''
        This function returns a string constructed by a path stored in a list, i.e., in case of [h1,s1,s2,h2] it returns
        h1->s1->s2->h2
        :param list_of_path: List - the list containing a path
        :return: String: the path
        '''
        retVal = ""
        path_len=len(list_of_path)-1
        for i,hop in enumerate(list_of_path):
            if i < path_len:
                retVal += hop + "->"
            else:
                retVal += hop
        return retVal

    def calculate_all_pair_shortest_paths(self):
        '''
        This function calculates all shortest paths for all source and destinations
        Note: NetworkX also have similar function (all_pairs_shortest_path(G[, cutoff])), however that only gives one
        shortest path for a given (source,destination) pair
        :return: dictionary of dictionary of list of lists, e.g., h1:{h2:[[h1,s1,h2],[h1,s2,h2]]}
        '''
        all_paths=dict()
        for n in self.get_nodes(prefix='h'):
            all_paths[n] = dict()
            for m in self.get_nodes(prefix='h'):
                if n == m:
                    continue
                all_paths[n][m] = self._get_shortest_paths(n,m)

        self.log.info("Shortest paths were recalculated")
        self.shortest_paths=all_paths

    def get_all_pair_shortest_paths(self):
        '''
        This function returns the stored shortest path dictionary
        :return: dictionary of dictionary of list of lists, e.g., h1:{h2:[[h1,s1,h2],[h1,s2,h2]]}
        '''

        return self.shortest_paths


    def draw_graph(self):
        nx.draw(self._G, pos=nx.spring_layout(self._G))
        plt.savefig("/tmp/simple.png")  # save as png
        # plt.show()  # display

