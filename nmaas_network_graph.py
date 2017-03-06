import networkx as nx
import inspect

class NMaaS_Network_Graph():

    def __init__(self):
        self._G=nx.Graph()

    def __str__(self):
        graph_desc = "--- === Graph data === ---\n"
        graph_desc += " -- Nodes --\n"

        for node in self._G.nodes():
            graph_desc += "{}:\n".format(node)

            if node.startswith('h-'):
                for i in self._G.node[node]:
                    graph_desc += "  {}:{}\n".format(i,self._G.node[node][i])
            elif node.startswith('s-'):
                graph_desc += "  datapath_id: {}\n".format(self._G.node[node]['dp'].id)
                graph_desc += "  Port_data:\n"
                for port in self._G.node[node]['port']:
                    graph_desc += "    {}\n".format(port)

            else:
                #another kind of node. Currently, we do not have any other type
                pass
            # if node.startswith('s-'):
                #     #switches has more data
                #     graph_desc += "Datapath:{}\n".format(self._G.node[node][i].dp)
                #     graph_desc += "Port:{}\n".format(self._G.node[node][i].ports)

            graph_desc += "\n"

        graph_desc += "\n -- Edges --\n"
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

    def get_nodes(self):
        return self._G.nodes()

    def add_edge(self, src, dst, **kwargs):
        self._G.add_edge(src, dst, kwargs)

    def remove_edge(self, src, dst):
        self._G.remove_edge(src, dst)

    def add_edges_from_list(self, list_of_src_dst_pairs, **kwargs):
        self._G.add_edges_from(list_of_src_dst_pairs, kwargs)

    def remove_edges_from_list(self, list_of_src_dst_pairs):
        self._G.remove_edges_from(list_of_src_dst_pairs)

    def get_edtes(self):
        return self._G.edges()

    def clear_graph(self):
        self._G.clear()

    def get_graph(self):
        return self._G

    def get_path(self,src, dst):
        if src not in self._G.nodes() or dst not in self._G.nodes():
            return None

        for path in nx.all_simple_paths(self._G, source=src, target=dst):
            return path


