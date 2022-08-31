#   Copyright 2022 Xieyang Xu
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
import pyvis.network
import networkx as nx
from treelib import Tree
from .datamodel import *

def visualize_dependency_graph(network: Network) -> pyvis.network.Network:
    G = nx.DiGraph()
    for node in network.graph.nodes:
        if isinstance(node, DataplaneTestNode):
            group = 1
        elif isinstance(node, RouteNode):
            group = 2
        elif isinstance(node, ConfigNode):
            group = 3
        else:
            group = 4
        G.add_node(str(node), group=group)
    for node in network.graph.nodes:
        for pred in node.pred:
            G.add_edge(str(pred), str(node))

    nt = pyvis.network.Network(height=800, width=800, notebook=True, directed=True)
    nt.toggle_hide_edges_on_drag(True)
    nt.from_nx(G)
    return nt

def print_dependency_graph_as_tree(tested_nodes: Iterable[DNode]) -> None:
    trees = []

    visited_nodes = set()
    def dfs(node: DNode, parent: DNode = None, tree: Tree = None):
        repr = str(node)
        if parent == None:
            tree = Tree()
            trees.append(tree)
            tree.create_node(repr, repr)
        else:
            id = repr
            while tree.contains(id):
                id = id + "*"
            tree.create_node(id, id, parent=str(parent))

        if node in visited_nodes:
            return

        visited_nodes.add(node)
        for (pred, _) in node.pred:
            dfs(pred, node, tree)

    for node in tested_nodes:
        dfs(node)

    for tree in trees:
        tree.show()