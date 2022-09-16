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
from __future__ import annotations # type hint in the enclosing class
import json
import logging
from typing import Iterable, Optional, Set
from pybatfish.datamodel.acl import TraceTreeList, TraceElement
import numpy as np

from .netstate import *
from .utils import *

class DNode:
    def __init__(self) -> None:
        self.pred: Set[Tuple[DNode, bool]] = set()
        self.status: Set[str] = {"init"}

    def add_dependency(self, node: DNode, is_weak=False):
        self.pred.add((node, is_weak))

    def print_dependency(self):
        res = [f"{pred} {'weak' if weak else 'strong'}" for (pred, weak) in self.pred]
        return "\n\t".join(res)
    
    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, DNode):
            return self.__hash__() == __o.__hash__()
        return NotImplemented

class DataplaneTestNode(DNode):
    def __init__(self, test_type, host, dst_ip, prefix, nexthop_ip, nexthop_interface) -> None:
        super().__init__()
        self.test_type: str = test_type
        self.host: str = host
        self.dst_ip: str = dst_ip
        self.prefix: str = prefix
        self.nexthop_ip: str = nexthop_ip
        self.nexthop_interface: str = nexthop_interface

    def __repr__(self) -> str:
        if self.test_type == "forwarded_to_ip":
            content = f"{self.dst_ip} -> {self.nexthop_interface}({self.nexthop_ip})"
        elif self.test_type == "forwarded_to_interface":
            content = f"{self.dst_ip} -> {self.nexthop_interface}"
        else:
            content = f"Unknown test type: {self.test_type}"
        
        return f"Tested@{self.host} {content}"

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.test_type, self.host, self.dst_ip, self.prefix, self.nexthop_ip, self.nexthop_interface))
    
    def toJson(self):
        d = {
            "test_type": self.test_type,
            "host": self.host,
            "dst_ip": self.dst_ip,
            "prefix": self.prefix,
            "nexthop_ip": self.nexthop_ip,
            "nexthop_interface": self.nexthop_interface,
        }
        return json.dumps(d)

    def from_dict(d: dict) -> DataplaneTestNode:
        return DataplaneTestNode(d["test_type"], d["host"], d["dst_ip"], d["prefix"], d["nexthop_ip"], d["nexthop_interface"])

class RouteNode(DNode):
    """Base class of route facts
    """
    def __init__(self, rib_type, prefix, nexthop, is_drop) -> None:
        super().__init__()
        self.rib_type: str = rib_type
        self.prefix: str = prefix
        self.nexthop: Optional[str] = nexthop
        self.is_drop: bool = is_drop

class MainRouteNode(RouteNode):
    def __init__(self, rib_type, prefix, nexthop, host, vrf, protocol, is_drop = False) -> None:
        super().__init__(rib_type, prefix, nexthop, is_drop)
        self.host: str = host
        self.vrf: str = vrf
        self.protocol: str = protocol

    def from_rec(rec: np.record) -> Optional[MainRouteNode]:
        if rec.Protocol in ['connected', 'local', 'static']:
            node_main = MainRouteNode("main", rec.Network, rec.Next_Hop_Interface, rec.Node, rec.VRF, rec.Protocol)
        elif rec.Protocol in ['bgp', 'ibgp', 'aggregate', 'isisL1', 'isisL2', 'isisEL1']:
            nexthop = rec.Next_Hop_IP
            if nexthop == None or nexthop == "AUTO/NONE(-1l)":
                nexthop = rec.Next_Hop_Interface
            node_main = MainRouteNode("main", rec.Network, nexthop, rec.Node, rec.VRF, rec.Protocol)
        else:
            logging.getLogger(__name__).warning(f"Unsupported protocol {rec.Protocol} with prefix {rec.Network} at {rec.Node}.{rec.VRF} main rib")
            node_main = None
        return node_main
    
    def __repr__(self) -> str:
        drop = "[drop]" if self.is_drop else ""
        return f"MainRoute@{self.host}.{self.vrf} {self.protocol}: {self.prefix} -> {self.nexthop}" + drop

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.rib_type, self.prefix, self.nexthop, self.host, self.vrf, self.protocol, self.is_drop))

class BgpAnnouncementNode(RouteNode):
    def __init__(self, rib_type, prefix, nexthop, sender, receiver, sender_vrf, receiver_vrf, pred_route, bgp_edge, trace, succ_node, is_drop = False) -> None:
        super().__init__(rib_type, prefix, nexthop, is_drop)
        self.sender: str = sender
        self.receiver: str = receiver
        self.sender_vrf: str = sender_vrf
        self.receiver_vrf: str = receiver_vrf
        # atributes for bgp export evaluation
        self.pred_route: BgpRoute = pred_route
        self.bgp_edge: Optional[BgpEdge] = bgp_edge
        self.trace: Optional[TraceTreeList] = trace
        # atribute to trigger bgp import evaluation at succ node
        # after export evaluation is done
        self.succ_node: Optional[BgpRouteNode] = succ_node

    def __repr__(self) -> str:
        drop = "[drop]" if self.is_drop else ""
        return f"RA@{self.sender}.{self.sender_vrf}->{self.receiver}.{self.receiver_vrf} {self.prefix}" + drop

    def __hash__(self) -> int:
        #return hash((self.__class__.__name__, self.rib_type, self.prefix, self.nexthop, self.sender, self.receiver,\
        #    self.sender_vrf, self.receiver_vrf, unpack_bgp_route(self.pred_route), self.is_drop))
        return hash((self.__class__.__name__, self.rib_type, self.prefix, self.nexthop, self.sender, self.receiver,\
            self.sender_vrf, self.receiver_vrf, self.is_drop))

class BgpRouteNode(RouteNode):
    def __init__(self, rib_type, prefix, nexthop, host, vrf, protocol, origin_protocol, as_path, route_status, received_from_ip, is_drop = False) -> None:
        super().__init__(rib_type, prefix, nexthop, is_drop)
        self.host: str = host
        self.vrf: str = vrf
        self.protocol: str = protocol
        self.origin_protocol: str = origin_protocol
        self.as_path: List[List[int]] = as_path
        self.route_status: str = route_status
        self.received_from_ip: str = received_from_ip
        # atributes for bgp import evaluation
        self.pred_route: Optional[BgpRoute] = None
        self.import_policy: Optional[Iterable[str]] = None
        self.trace: Optional[TraceTreeList] = None
        # atribute for "bgp_from_border_bgp_session"
        self.from_session: Optional[BgpSessionStatus] = None

    def from_rec(rec: np.record) -> Optional[BgpRouteNode]:
        if rec.Protocol == "bgp" or rec.Protocol == "aggregate" or rec.Protocol == "ibgp":
            if rec.Origin_Protocol == "connected":
                nexthop = rec.Next_Hop_Interface
                if nexthop == "null_interface":
                    nexthop = rec.Next_Hop_IP
            else:
                nexthop = rec.Next_Hop_IP
                if nexthop == None:
                    nexthop = rec.Next_Hop_Interface
            node_bgp = BgpRouteNode("bgp", rec.Network, nexthop, rec.Node, rec.VRF, rec.Protocol, rec.Origin_Protocol, convert_as_path(rec.AS_Path), rec.Status[0], rec.Received_From_IP)
        else:
            logging.getLogger(__name__).warning(f"Unsupported protocol {rec.Protocol} with prefix {rec.Network} at {rec.Node}.{rec.VRF} bgp")
            node_bgp = None
        return node_bgp

    def __repr__(self) -> str:
        drop = "[drop]" if self.is_drop else ""
        return f"BGPRoute@{self.host}.{self.vrf} {self.prefix} -> {self.nexthop}" + drop

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.rib_type, self.prefix, self.nexthop, self.host, self.vrf, self.protocol,\
            self.origin_protocol, unpack_as_path(self.as_path), self.route_status, self.is_drop))
    
    def top_of_as_path_matches(self, nexthop_as: int) -> bool:
        if len(self.as_path) > 0 and len(self.as_path[0]) > 0 and self.as_path[0][0] == nexthop_as:
            return True
        return False

class ConnectedRouteNode(RouteNode):
    def __init__(self, rib_type, prefix, nexthop, host, vrf, protocol, is_drop = False) -> None:
        super().__init__(rib_type, prefix, nexthop, is_drop)
        self.host: str = host
        self.vrf: str = vrf
        self.protocol: str = protocol

    def from_rec(rec: np.record) -> Optional[ConnectedRouteNode]:
        if rec.Protocol == 'connected' or rec.Protocol == "local" or rec.Protocol == "static":
            node_connected = ConnectedRouteNode("connected", rec.Network, rec.Next_Hop_Interface, rec.Node, rec.VRF, rec.Protocol)
        else:
            logging.getLogger(__name__).warning(f"Unsupported protocol {rec.Protocol} with prefix {rec.Prefix} at {rec.Node}.{rec.VRF} connected rib")
            node_connected = None
        return node_connected

    def __repr__(self) -> str:
        drop = "[drop]" if self.is_drop else ""
        return f"ConnectedRoute@{self.host}.{self.vrf}({self.protocol}) {self.prefix} -> {self.nexthop}" + drop

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.rib_type, self.prefix, self.nexthop, self.host, self.vrf, self.protocol, self.is_drop))

class ConfigNode(DNode):
    """base class of config facts"""
    def __init__(self, host, config_type) -> None:
        super().__init__()
        self.host: str = host
        self.config_type: str = config_type

class UserSuppliedConfigNode(ConfigNode):
    def __init__(self, host, lines, config_type='user-supplied') -> None:
        super().__init__(host, config_type)
        self.lines: FileLines = lines

    def __repr__(self) -> str:
        return f"{self.config_type}@{self.host}"

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.host, self.config_type, *self.lines))

class RoutemapNode(ConfigNode):
    def __init__(self, host, config_type, name, lines) -> None:
        super().__init__(host, config_type)
        self.name: str = name
        self.lines: FileLines = lines

    def __repr__(self) -> str:
        return f"Routemap@{self.host} {self.name}"

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.host, self.config_type, self.name))

class RoutemapClauseNode(ConfigNode):
    def __init__(self, host, config_type, name, seq, lines) -> None:
        super().__init__(host, config_type)
        self.name: str = name
        self.seq: str = seq
        self.lines: FileLines = lines

    def __repr__(self) -> str:
        return f"RM-Clause@{self.host} {self.name}"

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.host, self.config_type, self.name, self.seq))

class BgpPeerConfigNode(ConfigNode):
    def __init__(self, host, vrf, config_type, is_passive, local_as, export_policies, import_policies, peer_group, lines) -> None:
        super().__init__(host, config_type)
        self.vrf: str = vrf
        self.is_passive: bool = is_passive
        self.local_as: int = local_as
        self.export_policies: List[str] = export_policies
        self.import_policies: List[str] = import_policies
        self.peer_group: str = peer_group
        self.lines: FileLines = lines

class BgpPeerConfigP2pNode(BgpPeerConfigNode):
    def __init__(self, host, vrf, config_type, is_passive, local_as, export_policies, import_policies, peer_group, lines, local_ip, remote_ip, remote_as) -> None:
        super().__init__(host, vrf, config_type, is_passive, local_as, export_policies, import_policies, peer_group, lines)
        self.local_ip: str = local_ip
        self.remote_ip: str = remote_ip
        self.remote_as: int = remote_as
    
    def from_config(config: BgpPeerConfigP2p):
        return BgpPeerConfigP2pNode(config.host, config.vrf, "bgp_peer_config_p2p", config.is_passive, config.local_as, config.export_policies, config.import_policies, config.peer_group, config.lines, config.local_ip, config.remote_ip, config.remote_as)
    
    def __repr__(self) -> str:
        return f"BgpPeerP2pConfig@{self.host}.{self.vrf} peer:{self.remote_as}@{self.remote_ip}"

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.host, self.vrf, self.config_type, self.is_passive, self.local_as, self.local_ip, self.remote_ip, self.remote_as, self.peer_group))

class BgpPeerConfigPassiveNode(BgpPeerConfigNode):
    def __init__(self, host, vrf, config_type, is_passive, local_as, export_policies, import_policies, peer_group, lines, listen_range) -> None:
        super().__init__(host, vrf, config_type, is_passive, local_as, export_policies, import_policies, peer_group, lines)
        self.listen_range: str = listen_range

    def from_config(config: BgpPeerConfigPassive):
        return BgpPeerConfigPassiveNode(config.host, config.vrf, "bgp_peer_config_passive", config.is_passive, config.local_as, config.export_policies, config.import_policies, config.peer_group, config.lines, config.listen_range)

    def __repr__(self) -> str:
        return f"BgpPeerPassiveConfig@{self.host}.{self.vrf} listen range:{self.listen_range}"

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.host, self.vrf, self.config_type, self.is_passive, self.local_as, self.export_policies, self.import_policies, self.peer_group, self.listen_range))

class BgpGroupConfigNode(ConfigNode):
    def __init__(self, host, vrf, config_type, group_name, lines) -> None:
        super().__init__(host, config_type)
        self.vrf: str = vrf
        self.name: str = group_name
        self.lines: FileLines = lines

    def from_config(config: BgpGroupConfig):
        return BgpGroupConfigNode(config.host, config.vrf, "bgp_group", config.name, config.lines)

    def __repr__(self) -> str:
        return f"BgpPeerGroup@{self.host}.{self.vrf} {self.name}"
    
    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.host, self.vrf, self.config_type, self.name))

class InterfaceConfigNode(ConfigNode):
    def __init__(self, host, config_type, name, lines) -> None:
        super().__init__(host, config_type)
        self.name: str = name
        self.lines: FileLines = lines

    def from_interface(it: InterfaceConfig) -> InterfaceConfigNode:
        return InterfaceConfigNode(it.host, "interface", it.name, it.lines)

    def __repr__(self) -> str:
        return f"Interface[{self.name}]@{self.host}" 

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.host, self.config_type, self.name))

class ReferencedConfigNode(ConfigNode):
    def __init__(self, host, config_type, name, lines) -> None:
        super().__init__(host, config_type)
        self.name: str = name
        self.lines: FileLines = lines

    def from_config(config: ReferencedConfig) -> ReferencedConfigNode:
        return ReferencedConfigNode(config.host, config.config_type, config.name, config.lines)

    def __repr__(self) -> str:
        return f"{self.config_type.title()}@{self.host} {self.name}" 

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.host, self.config_type, self.name))

class EstablishedBgpSessionNode(DNode):
    def __init__(self, host, vrf, peer, peer_vrf, local_as, remote_as, local_ip, remote_ip, local_interface, remote_interface, session_type, is_border) -> None:
        super().__init__()
        self.host: str = host
        self.vrf: str = vrf
        self.peer: str = peer
        self.peer_vrf: str = peer_vrf
        self.local_as: int = local_as
        self.remote_as: int = remote_as
        self.local_ip: Optional[str] = local_ip
        self.remote_ip: Optional[str] = remote_ip
        self.local_interface: Optional[str] = local_interface
        self.remote_interface: Optional[str] = remote_interface
        self.session_type: str = session_type
        self.is_border: bool = is_border

    def from_session(s: BgpSessionStatus, peer_vrf: str) -> Optional[EstablishedBgpSessionNode]:
        if s.established_status == "ESTABLISHED":
            return EstablishedBgpSessionNode(s.host, s.vrf, s.peer, peer_vrf, s.local_as, s.remote_as, s.local_ip, s.remote_ip, s.local_interface, s.remote_interface, s.session_type, s.is_border)
        else:
            return None

    def __repr__(self) -> str:
        return f"BgpSession@{self.host}.{self.vrf}({self.local_as}, {self.local_ip})-{self.peer}({self.remote_as}, {self.remote_ip})"

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.host, self.vrf, self.peer, self.local_as, self.remote_as, self.local_ip, self.remote_ip, self.local_interface, self.remote_interface, self.session_type))

# class L3BiConnectivityNode(DNode):
#     def __init__(self, host1, host2, vrf1, vrf2, ip1, ip2, ipprotocol, port1, port2) -> None:
#         super().__init__()
#         self.host1: str = host1
#         self.host2: str = host2
#         self.vrf1: str = vrf1
#         self.vrf2: str = vrf2
#         self.ip1: str = ip1
#         self.ip2: str = ip2
#         self.ipprocotol: str = ipprotocol
#         self.port1: str = port1
#         self.port2: str = port2

#     def __repr__(self) -> str:
#         return f"L3Connectivity: ({self.host1}.{self.vrf1}, {self.ip1}) <--> ({self.host2}.{self.vrf2}, {self.ip2})"

#     def forward(self) -> str:
#         return f"L3Connectivity: ({self.host1}.{self.vrf1}, {self.ip1}) -> ({self.host2}.{self.vrf2}, {self.ip2})"

#     def backward(self) -> str:
#         return f"L3Connectivity: ({self.host2}.{self.vrf2}, {self.ip2}) -> ({self.host1}.{self.vrf1}, {self.ip1})"

#     def __hash__(self) -> int:
#         return hash((self.__class__.__name__, frozenset([(self.host1, self.vrf1, self.ip1, self.port1), (self.host2, self.vrf2, self.ip2, self.port2)]), self.ipprocotol))

class L3ConnectivityNode(DNode):
    def __init__(self, host1, host2, vrf1, vrf2, ip1, ip2, ipprotocol, port1, port2) -> None:
        super().__init__()
        self.host1: str = host1
        self.host2: str = host2
        self.vrf1: str = vrf1
        self.vrf2: str = vrf2
        self.ip1: str = ip1
        self.ip2: str = ip2
        self.ipprocotol: str = ipprotocol
        self.port1: str = port1
        self.port2: str = port2

    def __repr__(self) -> str:
        return f"L3Connectivity: ({self.host1}.{self.vrf1}, {self.ip1}) -> ({self.host2}.{self.vrf2}, {self.ip2})"

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.host1, self.vrf1, self.ip1, self.port1, self.host2, self.vrf2, self.ip2, self.port2, self.ipprocotol))

class L3PathNode(DNode):
    def __init__(self, dst_ip, path) -> None:
        super().__init__()
        self.dst_ip: str = dst_ip
        self.path: Trace = path
        hops = []
        for hop in self.path:
            host = hop.node
            for step in hop.steps:
                if step.action == "FORWARDED":
                    hops.append(f"{host}[{step.detail.forwardingDetail.outputInterface}]")
                elif step.action == "ACCEPTED":
                    hops.append(f"{host}[{step.detail.interface}]")
        self.repr: str = ' -> '.join(hops)

    def __repr__(self) -> str:
        return f"L3Path: {self.dst_ip}@{self.repr}"

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.dst_ip, self.repr))

    