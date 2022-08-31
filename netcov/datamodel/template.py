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
from __future__ import annotations
from typing import Callable, List, Tuple

from .dnode import DNode
from .network import Network

class DependencyTemplate:
    """Template to encode one type of legit edges of dependency graph.
    It specifies the range of nodes it cares about (as listed in left_nodes)
    and given one of such node, the mapper computes where does the dependency 
    edge(s) go to/from, depending on the direction.
    @members
        left_nodes: iterable of DNode -> iterable of DNode
        direction: str
        mapper: DNode -> iterable of DNode
    """
    def __init__(self, name, left_nodes, direction, mapper):
        self.name = name
        self.left_nodes = left_nodes
        self.direction = direction
        self.mapper = mapper

class LazyTemplate:
    """Template to encode one type of legit edges of dependency graph.
    It specifies the range of nodes it cares about (as listed in left_nodes)
    and given one of such node, the mapper computes where does the dependency 
    edge(s) go to/from, depending on the direction.
    @members
        filter: DNode -> a boolean indicating that whether this template is applicable for given node
        worker: DNode -> [parent nodes], [dirty nodes to be enqueued], [new nodes to be saved]
    """
    def __init__(self, name, matcher, worker, state_transition, edge_type):
        self.name: str = name
        self.matcher: Callable[[DNode], bool] = matcher
        self.worker: Callable[[Network, DNode], Tuple[List[DNode], List[DNode], List[DNode]]] = worker
        self.state_transition: Callable[[DNode], None] = state_transition
        self.edge_type: str = edge_type

    def default_state_transition(node: DNode) -> None:
        if "init" in node.status:
            node.status.remove("init")

    def null_state_transition(node: DNode) -> None:
        pass
