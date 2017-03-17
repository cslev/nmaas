import networkx as nx
import inspect
from networkx.algorithms.shortest_paths.weighted import all_pairs_dijkstra_path

try:
    import matplotlib.pyplot as plt
except:
    raise

class NMaaS_Network_Graph():

    def __init__(self):
        self._G=nx.Graph()

    def __str__(self):
        graph_desc = "--- === Graph data === ---\n"
        graph_desc += " -- Nodes --\n"

        for node in self._G.nodes():
            graph_desc += "{}:\n".format(node)

            if node.startswith('h'):
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
        print(self._G.edges())
        for edge in self._G.edges():
            graph_desc += "Between {} and {}:\n".format(edge[0], edge[1])
            graph_desc += "  {}\n".format(self._G.edge[edge[0]][edge[1]])

        graph_desc += "--------------------"

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
        for i in self.get_nodes(prefix='h'):
            if self._G.node[i]['ipv4'][0] == ip:
                return i

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
        if src not in self._G.nodes() or dst not in self._G.nodes():
            return None

        paths = list()
        for path in nx.all_simple_paths(self._G, src, dst):
            paths.append(path)
            # return path

        return paths

    def draw_graph(self):
        nx.draw(self._G, pos=nx.spring_layout(self._G))
        plt.savefig("/tmp/simple.png")  # save as png
        # plt.show()  # display

